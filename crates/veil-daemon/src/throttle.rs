//! Login throttling: failed sign-ins are counted per client address and per account, and a
//! source over its limit is refused before its password is checked.
//!
//! The counts live in memory. The service runs as one replica, and a restart clearing them
//! gives an attacker one fresh window, not a bypass.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::Mutex,
};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::request::Parts,
};

use crate::app::AppState;

/// How long a failure counts, in seconds.
pub const WINDOW_SECONDS: u64 = 15 * 60;
/// Failures one account may collect in a window, from any address.
pub const ACCOUNT_LIMIT: usize = 10;
/// Failures one client address may collect in a window, across accounts.
pub const ADDRESS_LIMIT: usize = 30;
/// Above this many tracked sources, expired ones are dropped on the next failure.
const PRUNE_ABOVE: usize = 10_000;

/// What a failure is counted against.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Source {
    /// A client address; IPv6 by its /64, the smallest block one client usually controls.
    Address(IpAddr),
    /// A normalized sign-in address.
    Account(String),
}

/// Failure times per source.
#[derive(Debug, Default)]
pub struct Throttle {
    failures: Mutex<HashMap<Source, Vec<u64>>>,
}

/// A refusal: how many seconds until the oldest counted failure expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limited {
    /// Seconds to wait before trying again.
    pub retry_after: u64,
}

impl Throttle {
    /// Refuses when the client address or the account is over its limit.
    pub fn check(&self, client: ClientIp, account: &str, at: u64) -> Result<(), Limited> {
        let failures = self.failures.lock().expect("throttle lock");
        for (source, limit) in sources(client, account) {
            let Some(times) = failures.get(&source) else {
                continue;
            };
            let live: Vec<u64> = times
                .iter()
                .copied()
                .filter(|time| at < time + WINDOW_SECONDS)
                .collect();
            if live.len() >= limit {
                let oldest = live.iter().min().copied().unwrap_or(at);
                return Err(Limited {
                    retry_after: (oldest + WINDOW_SECONDS).saturating_sub(at).max(1),
                });
            }
        }
        Ok(())
    }

    /// Counts a failed sign-in against the client address and the account.
    pub fn fail(&self, client: ClientIp, account: &str, at: u64) {
        let mut failures = self.failures.lock().expect("throttle lock");
        if failures.len() > PRUNE_ABOVE {
            failures.retain(|_, times| times.iter().any(|time| at < time + WINDOW_SECONDS));
        }
        for (source, _) in sources(client, account) {
            let times = failures.entry(source).or_default();
            times.retain(|time| at < time + WINDOW_SECONDS);
            times.push(at);
        }
    }

    /// Counts a failed sign-in and logs it. The log names the account by a short hash, never
    /// as typed: people type passwords into the username field.
    pub fn record_failure(&self, client: ClientIp, account: &str, at: u64, surface: &'static str) {
        self.fail(client, account, at);
        tracing::warn!(
            event = "sign-in-failed",
            surface,
            client = %client,
            account = %account_tag(account),
            "sign-in failed"
        );
    }

    /// Checks the limits and logs a refusal.
    pub fn admit(
        &self,
        client: ClientIp,
        account: &str,
        at: u64,
        surface: &'static str,
    ) -> Result<(), Limited> {
        self.check(client, account, at).inspect_err(|limited| {
            tracing::warn!(
                event = "sign-in-throttled",
                surface,
                client = %client,
                account = %account_tag(account),
                retry_after = limited.retry_after,
                "sign-in refused: too many failures"
            );
        })
    }

    /// Clears an account's failures after it signs in. The address keeps its count, so one
    /// valid account does not reset guessing against others.
    pub fn succeed(&self, account: &str) {
        let mut failures = self.failures.lock().expect("throttle lock");
        failures.remove(&Source::Account(normalize(account)));
    }
}

fn sources(client: ClientIp, account: &str) -> [(Source, usize); 2] {
    [
        (Source::Address(client.block()), ADDRESS_LIMIT),
        (Source::Account(normalize(account)), ACCOUNT_LIMIT),
    ]
}

fn normalize(account: &str) -> String {
    account.trim().to_lowercase()
}

/// Eight hex digits of the normalized account's SHA-256: enough to correlate log lines.
fn account_tag(account: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(normalize(account).as_bytes())
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// An address range trusted to proxy requests: `192.0.2.0/24`, `fd00::/8`, or one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    fn contains(self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

impl std::str::FromStr for Network {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = match text.trim().split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text.trim(), None),
        };
        let address: IpAddr = address
            .parse()
            .map_err(|_| format!("{text:?} is not an address or CIDR range"))?;
        let width = if address.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix
                .parse::<u8>()
                .ok()
                .filter(|prefix| *prefix <= width)
                .ok_or_else(|| format!("{text:?} has an invalid prefix length"))?,
            None => width,
        };
        Ok(Self { address, prefix })
    }
}

/// The client's address: the connection's peer, or, behind trusted proxies, the
/// `X-Forwarded-For` entry they vouch for. `None` when neither is known (in-process tests).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp(pub Option<IpAddr>);

impl ClientIp {
    /// Resolves the client from the peer and `X-Forwarded-For`. The header counts only when
    /// the peer is a trusted proxy; then it is read from the right, skipping trusted proxies,
    /// and the first other address is the client. Entries further left were written by the
    /// client, or by proxies nobody vouches for, and are ignored.
    pub fn resolve(peer: Option<IpAddr>, forwarded_for: Option<&str>, trusted: &[Network]) -> Self {
        let is_trusted = |address: &IpAddr| trusted.iter().any(|net| net.contains(*address));
        let Some(peer_address) = peer.filter(is_trusted) else {
            return Self(peer);
        };
        let mut client = peer_address;
        for entry in forwarded_for.unwrap_or("").rsplit(',') {
            let Ok(address) = entry.trim().parse::<IpAddr>() else {
                break;
            };
            client = address;
            if !is_trusted(&address) {
                break;
            }
        }
        Self(Some(client))
    }

    fn block(self) -> IpAddr {
        match self.0 {
            Some(IpAddr::V6(address)) => {
                let segments = address.segments();
                IpAddr::V6(Ipv6Addr::new(
                    segments[0],
                    segments[1],
                    segments[2],
                    segments[3],
                    0,
                    0,
                    0,
                    0,
                ))
            }
            Some(address) => address,
            None => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    }
}

impl std::fmt::Display for ClientIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(address) => write!(f, "{address}"),
            None => f.write_str("unknown"),
        }
    }
}

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let peer = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ConnectInfo(address)| address.ip());
        let forwarded_for = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok());
        let client = Self::resolve(peer, forwarded_for, &state.trusted_proxies);
        tracing::debug!(
            forwarded_for = forwarded_for.unwrap_or(""),
            peer = ?peer,
            client = %client,
            "client address"
        );
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> ClientIp {
        ClientIp(Some(text.parse().expect("ip")))
    }

    #[test]
    fn an_account_is_refused_after_its_limit_and_frees_up_after_the_window() {
        let throttle = Throttle::default();
        for n in 0..ACCOUNT_LIMIT {
            // Spread across addresses so only the account limit applies.
            let client = ip(&format!("198.51.100.{n}"));
            assert!(throttle.check(client, "Me@Example.com", 100).is_ok());
            throttle.fail(client, "me@example.com", 100);
        }
        let refused = throttle
            .check(ip("203.0.113.1"), "ME@example.com", 160)
            .expect_err("over the account limit");
        assert_eq!(refused.retry_after, WINDOW_SECONDS - 60);
        assert!(
            throttle
                .check(ip("203.0.113.1"), "me@example.com", 100 + WINDOW_SECONDS)
                .is_ok()
        );
    }

    #[test]
    fn an_address_is_refused_across_accounts() {
        let throttle = Throttle::default();
        let client = ip("203.0.113.7");
        for n in 0..ADDRESS_LIMIT {
            throttle.fail(client, &format!("user{n}@example.com"), 100);
        }
        assert!(throttle.check(client, "fresh@example.com", 101).is_err());
        assert!(
            throttle
                .check(ip("203.0.113.8"), "fresh@example.com", 101)
                .is_ok()
        );
    }

    #[test]
    fn ipv6_counts_by_64_block() {
        let throttle = Throttle::default();
        for n in 0..ADDRESS_LIMIT {
            let client = ip(&format!("2001:db8:1:2::{n:x}"));
            throttle.fail(client, &format!("user{n}@example.com"), 100);
        }
        assert!(
            throttle
                .check(ip("2001:db8:1:2:ffff::1"), "fresh@example.com", 101)
                .is_err()
        );
        assert!(
            throttle
                .check(ip("2001:db8:1:3::1"), "fresh@example.com", 101)
                .is_ok()
        );
    }

    #[test]
    fn success_clears_the_account_but_not_the_address() {
        let throttle = Throttle::default();
        let client = ip("198.51.100.1");
        for _ in 0..ACCOUNT_LIMIT {
            throttle.fail(client, "me@example.com", 100);
        }
        throttle.succeed("me@example.com");
        assert!(
            throttle
                .check(ip("198.51.100.2"), "me@example.com", 101)
                .is_ok()
        );
        for n in 0..ADDRESS_LIMIT - ACCOUNT_LIMIT {
            throttle.fail(client, &format!("other{n}@example.com"), 100);
        }
        assert!(throttle.check(client, "me@example.com", 101).is_err());
    }

    #[test]
    fn forwarded_for_counts_only_through_trusted_proxies() {
        let proxies: Vec<Network> = vec!["192.0.2.0/24".parse().expect("cidr")];
        let proxy = Some("192.0.2.9".parse().expect("ip"));
        // The nearest untrusted address wins, not a spoofed leftmost value.
        assert_eq!(
            ClientIp::resolve(
                proxy,
                Some("198.51.100.6, 203.0.113.9, 192.0.2.17"),
                &proxies
            ),
            ip("203.0.113.9")
        );
        // A single trusted proxy preserves the client address.
        assert_eq!(
            ClientIp::resolve(proxy, Some("203.0.113.20"), &proxies),
            ip("203.0.113.20")
        );
        // Without a header, or from an untrusted peer, the peer is the client.
        assert_eq!(ClientIp::resolve(proxy, None, &proxies), ClientIp(proxy));
        let stranger = Some("198.51.100.4".parse().expect("ip"));
        assert_eq!(
            ClientIp::resolve(stranger, Some("192.0.2.1"), &proxies),
            ClientIp(stranger)
        );
        // Nothing trusted: the header is ignored.
        assert_eq!(
            ClientIp::resolve(proxy, Some("203.0.113.9"), &[]),
            ClientIp(proxy)
        );
        // Garbage stops the walk at the last good address.
        assert_eq!(
            ClientIp::resolve(proxy, Some("203.0.113.9, junk, 192.0.2.17"), &proxies),
            ip("192.0.2.17")
        );
    }

    #[test]
    fn networks_parse_and_match() {
        let v4: Network = "192.0.2.0/24".parse().expect("v4");
        assert!(v4.contains("192.0.2.255".parse().expect("ip")));
        assert!(!v4.contains("198.51.100.1".parse().expect("ip")));
        let one: Network = "127.0.0.1".parse().expect("single");
        assert!(one.contains("127.0.0.1".parse().expect("ip")));
        let v6: Network = "fd00::/8".parse().expect("v6");
        assert!(v6.contains("fd12::1".parse().expect("ip")));
        assert!(!v6.contains("192.0.2.1".parse().expect("ip")));
        assert!("192.0.2.0/33".parse::<Network>().is_err());
        assert!("nonsense".parse::<Network>().is_err());
    }
}
