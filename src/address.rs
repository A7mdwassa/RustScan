//! Provides functions to parse input IP addresses, CIDRs or files.
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{prelude::*, BufReader};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

use cidr_utils::cidr::{IpCidr, IpInet};
use hickory_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts},
    Resolver,
};
use log::debug;

use crate::input::Opts;
use crate::warning;

/// Default chunk size used when streaming IPs to keep peak memory bounded.
pub const STREAM_CHUNK_SIZE: usize = 65_536;

/// Parses the string(s) into IP addresses.
///
/// Goes through all possible IP inputs (files or via argparsing).
///
/// ```rust
/// # use rustscan::input::Opts;
/// # use rustscan::address::parse_addresses;
/// let mut opts = Opts::default();
/// opts.addresses = vec!["192.168.0.0/30".to_owned()];
///
/// let ips = parse_addresses(&opts);
/// ```
///
/// Finally, any duplicates are removed to avoid excessive scans.
pub fn parse_addresses(input: &Opts) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();
    let mut unresolved_addresses: Vec<&str> = Vec::new();
    let backup_resolver = get_resolver(&input.resolver);

    for address in &input.addresses {
        let parsed_ips = parse_address(address, &backup_resolver);
        if !parsed_ips.is_empty() {
            ips.extend(parsed_ips);
        } else {
            unresolved_addresses.push(address);
        }
    }

    // If we got to this point this can only be a file path or the wrong input.
    for file_path in unresolved_addresses {
        let file_path = Path::new(file_path);

        if !file_path.is_file() {
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );

            continue;
        }

        if let Err(e) = read_ips_from_file(file_path, &backup_resolver, &mut ips) {
            debug!("Failed to read IPs from {file_path:?}: {e}");
            warning!(
                format!("Host {file_path:?} could not be resolved."),
                input.greppable,
                input.accessible
            );
        }
    }

    let excluded_cidrs = parse_excluded_networks(&input.exclude_addresses, &backup_resolver);

    // Remove duplicated/excluded IPs.
    let mut seen = BTreeSet::new();
    ips.retain(|ip| seen.insert(*ip) && !excluded_cidrs.iter().any(|cidr| cidr.contains(ip)));

    ips
}

/// Streaming variant of [`parse_addresses`] that never holds all IPs in memory.
///
/// IPs (from CLI args and/or newline-delimited files) are produced in fixed-size
/// chunks. CIDR ranges are expanded lazily, one address at a time, so even a /8
/// never materialises fully — peak memory is bounded by `chunk_size`.
///
/// The callback `f` is invoked once per full chunk and once more with any
/// remainder. Dedup/exclusion runs per-chunk only; cross-chunk dups are not
/// removed (holding every IP to dedup globally is itself the OOM we're avoiding
/// on inputs like cn.txt — a few extra connection attempts beat gigabytes of RAM).
///
/// Returns the total number of IPs yielded across all chunks.
pub fn parse_addresses_chunked<F>(input: &Opts, chunk_size: usize, mut f: F) -> usize
where
    F: FnMut(&[IpAddr]),
{
    let backup_resolver = get_resolver(&input.resolver);
    let excluded_cidrs = parse_excluded_networks(&input.exclude_addresses, &backup_resolver);

    let mut chunk: Vec<IpAddr> = Vec::with_capacity(chunk_size);
    // ponytail: per-chunk seen set. A global seen set on 300M+ IPs is itself
    // the OOM source; clearing per chunk bounds memory to chunk_size.
    let mut seen: BTreeSet<IpAddr> = BTreeSet::new();
    let mut total = 0usize;

    macro_rules! flush {
        () => {{
            if !chunk.is_empty() {
                total += chunk.len();
                f(&chunk);
                chunk.clear();
                seen.clear();
            }
        }};
    }

    // Push one IP through dedup/exclusion, flushing when the chunk is full.
    macro_rules! push {
        ($ip:expr) => {{
            let ip = $ip;
            if seen.insert(ip) && !excluded_cidrs.iter().any(|cidr| cidr.contains(&ip)) {
                chunk.push(ip);
                if chunk.len() >= chunk_size {
                    flush!();
                }
            }
        }};
    }

    // Expand one address spec (IP / CIDR / hostname) lazily into the chunk.
    macro_rules! expand {
        ($addr:expr) => {{
            let address = $addr;
            if let Ok(addr) = IpAddr::from_str(address) {
                push!(addr);
            } else if let Ok(net_addr) = IpInet::from_str(address) {
                // Lazy CIDR iteration — never collects the whole range.
                for ip in net_addr.network().into_iter().addresses() {
                    push!(ip);
                }
            } else {
                // Hostname: resolve (small result set), then push.
                match format!("{address}:80").to_socket_addrs() {
                    Ok(mut iter) => {
                        if let Some(sock) = iter.next() {
                            push!(sock.ip());
                        }
                    }
                    Err(_) => {
                        for ip in resolve_ips_from_host(address, &backup_resolver) {
                            push!(ip);
                        }
                    }
                }
            }
        }};
    }

    // 1) Direct CLI args.
    for address in &input.addresses {
        expand!(address.as_str());
    }

    // 2) File paths (args that didn't resolve directly as IP/CIDR/hostname).
    for address in &input.addresses {
        if IpAddr::from_str(address).is_ok() || IpInet::from_str(address).is_ok() {
            continue;
        }
        let path = Path::new(address.as_str());
        if !path.is_file() {
            continue;
        }
        let Ok(file) = File::open(path) else { continue };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            expand!(line.trim());
        }
    }

    // Final partial chunk.
    flush!();
    total
}

/// Given a string, parse it as a host, IP address, or CIDR.
///
/// This allows us to pass files as hosts or cidr or IPs easily
/// Call this every time you have a possible IP-or-host.
///
/// If the address is a domain, we can self-resolve the domain locally
/// or resolve it by the dns resolver list.
///
/// ```rust
/// # use rustscan::address::parse_address;
/// # use hickory_resolver::Resolver;
/// let ips = parse_address("127.0.0.1", &Resolver::default().unwrap());
/// ```
pub fn parse_address(address: &str, resolver: &Resolver) -> Vec<IpAddr> {
    if let Ok(addr) = IpAddr::from_str(address) {
        // `address` is an IP string
        vec![addr]
    } else if let Ok(net_addr) = IpInet::from_str(address) {
        // `address` is a CIDR string
        net_addr.network().into_iter().addresses().collect()
    } else {
        // `address` is a hostname or DNS name
        // attempt default DNS lookup
        match format!("{address}:80").to_socket_addrs() {
            Ok(mut iter) => vec![iter.next().unwrap().ip()],
            // default lookup didn't work, so try again with the dedicated resolver
            Err(_) => resolve_ips_from_host(address, resolver),
        }
    }
}

/// Uses DNS to get the IPS associated with host
fn resolve_ips_from_host(source: &str, backup_resolver: &Resolver) -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = Vec::new();

    if let Ok(addrs) = source.to_socket_addrs() {
        for ip in addrs {
            ips.push(ip.ip());
        }
    } else if let Ok(addrs) = backup_resolver.lookup_ip(source) {
        ips.extend(addrs.iter());
    }

    ips
}

/// Parses excluded networks from a list of addresses.
///
/// This function handles three types of inputs:
/// 1. CIDR notation (e.g. "192.168.0.0/24")
/// 2. Single IP addresses (e.g. "192.168.0.1")
/// 3. Hostnames that need to be resolved (e.g. "example.com")
///
/// ```rust
/// # use rustscan::address::parse_excluded_networks;
/// # use hickory_resolver::Resolver;
/// let resolver = Resolver::default().unwrap();
/// let excluded = parse_excluded_networks(&Some(vec!["192.168.0.0/24".to_owned()]), &resolver);
/// ```
pub fn parse_excluded_networks(
    exclude_addresses: &Option<Vec<String>>,
    resolver: &Resolver,
) -> Vec<IpCidr> {
    exclude_addresses
        .iter()
        .flatten()
        .flat_map(|addr| parse_single_excluded_address(addr, resolver))
        .collect()
}

/// Parses a single address into an IpCidr, handling CIDR notation, IP addresses, and hostnames.
fn parse_single_excluded_address(addr: &str, resolver: &Resolver) -> Vec<IpCidr> {
    if let Ok(cidr) = IpCidr::from_str(addr) {
        return vec![cidr];
    }

    if let Ok(ip) = IpAddr::from_str(addr) {
        return vec![IpCidr::new_host(ip)];
    }

    resolve_ips_from_host(addr, resolver)
        .into_iter()
        .map(IpCidr::new_host)
        .collect()
}

/// Derive a DNS resolver.
///
/// 1. if the `resolver` parameter has been set:
///     1. assume the parameter is a path and attempt to read IPs.
///     2. parse the input as a comma-separated list of IPs.
/// 2. if `resolver` is not set:
///    1. attempt to derive a resolver from the system config. (e.g.
///       `/etc/resolv.conf` on *nix).
///    2. finally, build a CloudFlare-based resolver (default
///       behaviour).
fn get_resolver(resolver: &Option<String>) -> Resolver {
    match resolver {
        Some(r) => {
            let mut config = ResolverConfig::new();
            let resolver_ips = match read_resolver_from_file(r) {
                Ok(ips) => ips,
                Err(_) => r
                    .split(',')
                    .filter_map(|r| IpAddr::from_str(r).ok())
                    .collect::<Vec<_>>(),
            };
            for ip in resolver_ips {
                config.add_name_server(NameServerConfig::new(
                    SocketAddr::new(ip, 53),
                    Protocol::Udp,
                ));
            }
            Resolver::new(config, ResolverOpts::default()).unwrap()
        }
        None => match Resolver::from_system_conf() {
            Ok(resolver) => resolver,
            Err(_) => {
                Resolver::new(ResolverConfig::cloudflare_tls(), ResolverOpts::default()).unwrap()
            }
        },
    }
}

/// Parses and input file of IPs for use in DNS resolution.
fn read_resolver_from_file(path: &str) -> Result<Vec<IpAddr>, std::io::Error> {
    let ips = fs::read_to_string(path)?
        .lines()
        .filter_map(|line| IpAddr::from_str(line.trim()).ok())
        .collect();

    Ok(ips)
}

#[cfg(not(tarpaulin_include))]
/// Parses an input file of IPs and uses those
fn read_ips_from_file(
    path: &std::path::Path,
    backup_resolver: &Resolver,
    ips: &mut Vec<IpAddr>,
) -> Result<(), std::io::Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);

    for address_line in reader.lines() {
        if let Ok(address) = address_line {
            ips.extend(parse_address(&address, backup_resolver));
        } else {
            debug!("Line in file is not valid");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{get_resolver, parse_addresses, Opts};
    use std::net::Ipv4Addr;

    #[test]
    fn parse_correct_addresses() {
        let opts = Opts {
            addresses: vec!["127.0.0.1".to_owned(), "192.168.0.0/30".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(127, 0, 0, 1),
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 1),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_addresses_with_address_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/30".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.1".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_addresses_with_cidr_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/29".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.0/30".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 4),
                Ipv4Addr::new(192, 168, 0, 5),
                Ipv4Addr::new(192, 168, 0, 6),
                Ipv4Addr::new(192, 168, 0, 7),
            ]
        );
    }

    #[test]
    fn parse_addresses_with_incorrect_address_exclusions() {
        let opts = Opts {
            addresses: vec!["192.168.0.0/30".to_owned()],
            exclude_addresses: Some(vec!["192.168.0.1".to_owned()]),
            ..Default::default()
        };
        let ips = parse_addresses(&opts);

        assert_eq!(
            ips,
            [
                Ipv4Addr::new(192, 168, 0, 0),
                Ipv4Addr::new(192, 168, 0, 2),
                Ipv4Addr::new(192, 168, 0, 3)
            ]
        );
    }

    #[test]
    fn parse_correct_host_addresses() {
        let opts = Opts {
            addresses: vec!["google.com".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 1);
    }

    #[test]
    fn parse_correct_and_incorrect_addresses() {
        let opts = Opts {
            addresses: vec!["127.0.0.1".to_owned(), "im_wrong".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips, [Ipv4Addr::new(127, 0, 0, 1),]);
    }

    #[test]
    fn parse_incorrect_addresses() {
        let opts = Opts {
            addresses: vec!["im_wrong".to_owned(), "300.10.1.1".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert!(ips.is_empty());
    }

    #[test]
    fn parse_hosts_file_and_incorrect_hosts() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/hosts.txt".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 3);
    }

    #[test]
    fn parse_empty_hosts_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/empty_hosts.txt".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn parse_naughty_host_file() {
        // Host file contains IP, Hosts, incorrect IPs, incorrect hosts
        let opts = Opts {
            addresses: vec!["fixtures/naughty_string.txt".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 0);
    }

    #[test]
    fn parse_duplicate_cidrs() {
        let opts = Opts {
            addresses: vec!["79.98.104.0/21".to_owned(), "79.98.104.0/24".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 2_048);
    }

    #[test]
    fn parse_overspecific_cidr() {
        // a canonical CIDR string has 0 in all host bits, but we want to treat any CIDR-like string as CIDR
        let opts = Opts {
            addresses: vec!["192.128.1.1/24".to_owned()],
            ..Default::default()
        };

        let ips = parse_addresses(&opts);

        assert_eq!(ips.len(), 256);
    }

    #[test]
    fn resolver_args_google_dns() {
        // https://developers.google.com/speed/public-dns
        let opts = Opts {
            resolver: Some("8.8.8.8,8.8.4.4".to_owned()),
            ..Default::default()
        };

        let resolver = get_resolver(&opts.resolver);
        let lookup = resolver.lookup_ip("www.example.com.").unwrap();

        assert!(lookup.iter().next().is_some());
    }
}
