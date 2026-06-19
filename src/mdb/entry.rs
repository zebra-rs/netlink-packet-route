// SPDX-License-Identifier: MIT

//! Decoding of the nested bridge MDB entry tree carried under the
//! `MDBA_MDB` attribute of an `RTM_{NEW,DEL}MDB` message.
//!
//! The kernel encodes the multicast database as three levels of nested
//! netlink attributes:
//!
//! ```text
//! MDBA_MDB
//!   MDBA_MDB_ENTRY            (one per group)
//!     MDBA_MDB_ENTRY_INFO     (one per port/source)
//!       struct br_mdb_entry   (fixed 28 octets)
//!       MDBA_MDB_EATTR_SOURCE (optional, the (S) of an (S,G) entry)
//!       ... other eattrs ...
//! ```
//!
//! `br_mdb_entry` (linux/if_bridge.h) is:
//!
//! ```c
//! struct br_mdb_entry {
//!     __u32 ifindex;   // bridge port the group was learned on
//!     __u8  state;     // MDB_TEMPORARY (0) / MDB_PERMANENT (1)
//!     __u8  flags;     // MDB_FLAGS_*
//!     __u16 vid;
//!     struct {
//!         union { __be32 ip4; struct in6_addr ip6; __u8 mac_addr[6]; } u;
//!         __be16 proto;   // htons(ETH_P_IP|ETH_P_IPV6), 0 for an L2 MAC group
//!     } addr;
//! };
//! ```
//!
//! Integer fields (`ifindex`, `vid`) are host byte order; the address
//! union and `proto` are network byte order.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use netlink_packet_utils::nla::NlasIterator;

// Nesting kinds. Both inner containers happen to use kind 1.
const MDBA_MDB_ENTRY: u16 = 1;
const MDBA_MDB_ENTRY_INFO: u16 = 1;
// Per-entry extended attributes (under MDBA_MDB_ENTRY_INFO).
const MDBA_MDB_EATTR_SOURCE: u16 = 2;

// addr.proto values (network byte order on the wire).
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;

/// Fixed on-wire size of `struct br_mdb_entry` (NLMSG-aligned).
const BR_MDB_ENTRY_LEN: usize = 28;

/// The multicast group of an MDB entry. IGMP/MLD snooping yields IP
/// groups; statically-added L2 entries yield a MAC group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdbGroup {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Mac([u8; 6]),
}

/// One decoded bridge MDB entry (a single `MDBA_MDB_ENTRY_INFO`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdbEntry {
    /// Bridge port ifindex the group was learned on.
    pub port_ifindex: u32,
    /// `MDB_TEMPORARY` (0) / `MDB_PERMANENT` (1) / other.
    pub state: u8,
    /// `MDB_FLAGS_*` bitmask.
    pub flags: u8,
    /// Bridge VLAN id (0 when the bridge is not VLAN-aware).
    pub vid: u16,
    /// Multicast group address.
    pub group: MdbGroup,
    /// Source address for an `(S,G)` entry; `None` for `(*,G)`.
    pub source: Option<IpAddr>,
}

/// Decode every entry from a raw `MDBA_MDB` attribute payload. Malformed
/// sub-attributes are skipped rather than failing the whole decode (the
/// kernel may add eattrs this version doesn't model).
pub fn parse_mdb_entries(raw: &[u8]) -> Vec<MdbEntry> {
    let mut out = Vec::new();
    for entry in NlasIterator::new(raw) {
        let Ok(entry) = entry else { continue };
        if entry.kind() != MDBA_MDB_ENTRY {
            continue;
        }
        for info in NlasIterator::new(entry.value()) {
            let Ok(info) = info else { continue };
            if info.kind() != MDBA_MDB_ENTRY_INFO {
                continue;
            }
            if let Some(decoded) = parse_entry_info(info.value()) {
                out.push(decoded);
            }
        }
    }
    out
}

/// Parse one `MDBA_MDB_ENTRY_INFO` value: the fixed `br_mdb_entry`
/// struct followed by nested per-entry attributes.
fn parse_entry_info(value: &[u8]) -> Option<MdbEntry> {
    if value.len() < BR_MDB_ENTRY_LEN {
        return None;
    }
    let port_ifindex = u32::from_ne_bytes(value[0..4].try_into().ok()?);
    let state = value[4];
    let flags = value[5];
    let vid = u16::from_ne_bytes(value[6..8].try_into().ok()?);
    let proto = u16::from_be_bytes(value[24..26].try_into().ok()?);
    let group = match proto {
        ETH_P_IP => MdbGroup::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&value[8..12]).ok()?)),
        ETH_P_IPV6 => MdbGroup::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&value[8..24]).ok()?)),
        _ => {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&value[8..14]);
            MdbGroup::Mac(mac)
        }
    };

    // The (S) of an (S,G) entry rides in MDBA_MDB_EATTR_SOURCE after the
    // fixed struct.
    let mut source = None;
    for eattr in NlasIterator::new(&value[BR_MDB_ENTRY_LEN..]) {
        let Ok(eattr) = eattr else { continue };
        if eattr.kind() == MDBA_MDB_EATTR_SOURCE {
            source = match eattr.value().len() {
                4 => Some(IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(eattr.value()).ok()?,
                ))),
                16 => Some(IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(eattr.value()).ok()?,
                ))),
                _ => None,
            };
        }
    }

    Some(MdbEntry {
        port_ifindex,
        state,
        flags,
        vid,
        group,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build one NLA: [len u16][type u16][value][pad to 4].
    fn nla(kind: u16, value: &[u8]) -> Vec<u8> {
        let len = 4 + value.len();
        let mut out = Vec::new();
        out.extend_from_slice(&(len as u16).to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(value);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    // br_mdb_entry for an IPv4 group, optional source bytes appended as
    // an MDBA_MDB_EATTR_SOURCE nested attribute.
    fn entry_info_v4(port: u32, vid: u16, grp: Ipv4Addr, src: Option<Ipv4Addr>) -> Vec<u8> {
        let mut s = vec![0u8; BR_MDB_ENTRY_LEN];
        s[0..4].copy_from_slice(&port.to_ne_bytes());
        s[4] = 1; // permanent
        s[6..8].copy_from_slice(&vid.to_ne_bytes());
        s[8..12].copy_from_slice(&grp.octets());
        s[24..26].copy_from_slice(&ETH_P_IP.to_be_bytes());
        if let Some(src) = src {
            s.extend_from_slice(&nla(MDBA_MDB_EATTR_SOURCE, &src.octets()));
        }
        s
    }

    fn wrap(entry_infos: &[Vec<u8>]) -> Vec<u8> {
        // MDBA_MDB { MDBA_MDB_ENTRY { MDBA_MDB_ENTRY_INFO ... } }
        let mut entry_payload = Vec::new();
        for info in entry_infos {
            entry_payload.extend_from_slice(&nla(MDBA_MDB_ENTRY_INFO, info));
        }
        nla(MDBA_MDB_ENTRY, &entry_payload)
    }

    #[test]
    fn star_g_ipv4() {
        let raw = wrap(&[entry_info_v4(7, 0, Ipv4Addr::new(239, 1, 1, 1), None)]);
        let entries = parse_mdb_entries(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].port_ifindex, 7);
        assert_eq!(entries[0].group, MdbGroup::V4(Ipv4Addr::new(239, 1, 1, 1)));
        assert_eq!(entries[0].source, None);
    }

    #[test]
    fn s_g_ipv4() {
        let raw = wrap(&[entry_info_v4(
            9,
            10,
            Ipv4Addr::new(232, 0, 0, 5),
            Some(Ipv4Addr::new(192, 0, 2, 1)),
        )]);
        let entries = parse_mdb_entries(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].vid, 10);
        assert_eq!(entries[0].group, MdbGroup::V4(Ipv4Addr::new(232, 0, 0, 5)));
        assert_eq!(
            entries[0].source,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
    }

    #[test]
    fn ipv6_group() {
        let mut s = vec![0u8; BR_MDB_ENTRY_LEN];
        s[0..4].copy_from_slice(&3u32.to_ne_bytes());
        let grp: Ipv6Addr = "ff05::1:3".parse().unwrap();
        s[8..24].copy_from_slice(&grp.octets());
        s[24..26].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        let raw = wrap(&[s]);
        let entries = parse_mdb_entries(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group, MdbGroup::V6(grp));
    }

    #[test]
    fn multiple_entries() {
        let raw = wrap(&[
            entry_info_v4(7, 0, Ipv4Addr::new(239, 1, 1, 1), None),
            entry_info_v4(7, 0, Ipv4Addr::new(239, 2, 2, 2), None),
        ]);
        assert_eq!(parse_mdb_entries(&raw).len(), 2);
    }

    #[test]
    fn empty_is_empty() {
        assert!(parse_mdb_entries(&[]).is_empty());
    }
}
