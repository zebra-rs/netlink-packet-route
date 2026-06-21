// SPDX-License-Identifier: MIT

use netlink_packet_utils::{DecodeError, Emitable, Parseable};

use super::{TunnelHeader, TunnelMessageBuffer};
use crate::AddressFamily;

// linux/if_link.h: VXLAN_VNIFILTER_ENTRY = 1 (carried NESTED), with
// VXLAN_VNIFILTER_ENTRY_START = 1 holding the (single) VNI.
const NLA_F_NESTED: u16 = 0x8000;
const VXLAN_VNIFILTER_ENTRY: u16 = 1;
const VXLAN_VNIFILTER_ENTRY_START: u16 = 1;

/// A bridge VNI-filter message (`RTM_{NEW,DEL}TUNNEL`) — `bridge vni
/// add/del vni N dev <vtep>`. Each VNI is one `VXLAN_VNIFILTER_ENTRY`
/// (single VNI via `_START`; ranges are not modelled here).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TunnelMessage {
    pub header: TunnelHeader,
    pub vnis: Vec<u32>,
}

impl TunnelMessage {
    /// Build a single-VNI add/del for `ifindex`.
    pub fn vni(ifindex: u32, vni: u32) -> Self {
        TunnelMessage {
            header: TunnelHeader {
                family: AddressFamily::Bridge,
                flags: 0,
                index: ifindex,
            },
            vnis: vec![vni],
        }
    }
}

// One VXLAN_VNIFILTER_ENTRY (NESTED) wrapping VXLAN_VNIFILTER_ENTRY_START.
const ENTRY_LEN: usize = 4 + 4 + 4; // nested hdr + (inner hdr + u32)

impl<'a, T: AsRef<[u8]> + 'a> Parseable<TunnelMessageBuffer<&'a T>>
    for TunnelMessage
{
    fn parse(buf: &TunnelMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let header = TunnelHeader {
            family: AddressFamily::from(buf.family()),
            flags: buf.flags(),
            index: buf.index(),
        };
        let mut vnis = Vec::new();
        for nla in buf.nlas() {
            let Ok(nla) = nla else { continue };
            if nla.kind() & !NLA_F_NESTED != VXLAN_VNIFILTER_ENTRY {
                continue;
            }
            for inner in
                netlink_packet_utils::nla::NlasIterator::new(nla.value())
            {
                let Ok(inner) = inner else { continue };
                if inner.kind() == VXLAN_VNIFILTER_ENTRY_START {
                    if let Ok(b) = <[u8; 4]>::try_from(inner.value()) {
                        vnis.push(u32::from_ne_bytes(b));
                    }
                }
            }
        }
        Ok(TunnelMessage { header, vnis })
    }
}

impl Emitable for TunnelMessage {
    fn buffer_len(&self) -> usize {
        8 + self.vnis.len() * ENTRY_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(&mut buffer[..8]);
        let mut off = 8;
        for &vni in &self.vnis {
            // VXLAN_VNIFILTER_ENTRY (nested), len = ENTRY_LEN.
            buffer[off..off + 2]
                .copy_from_slice(&(ENTRY_LEN as u16).to_ne_bytes());
            buffer[off + 2..off + 4].copy_from_slice(
                &(VXLAN_VNIFILTER_ENTRY | NLA_F_NESTED).to_ne_bytes(),
            );
            // VXLAN_VNIFILTER_ENTRY_START, len 8, value = vni.
            buffer[off + 4..off + 6].copy_from_slice(&8u16.to_ne_bytes());
            buffer[off + 6..off + 8]
                .copy_from_slice(&VXLAN_VNIFILTER_ENTRY_START.to_ne_bytes());
            buffer[off + 8..off + 12].copy_from_slice(&vni.to_ne_bytes());
            off += ENTRY_LEN;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vni_add_roundtrip() {
        let msg = TunnelMessage::vni(2, 10);
        let mut buf = vec![0u8; msg.buffer_len()];
        msg.emit(&mut buf);
        // 8-byte header + 12-byte entry.
        assert_eq!(buf.len(), 20);
        assert_eq!(buf[0], u8::from(AddressFamily::Bridge));
        assert_eq!(&buf[4..8], &2u32.to_ne_bytes(), "ifindex");
        assert_eq!(
            &buf[8..10],
            &(ENTRY_LEN as u16).to_ne_bytes(),
            "entry nla len"
        );
        assert_eq!(
            &buf[10..12],
            &(VXLAN_VNIFILTER_ENTRY | NLA_F_NESTED).to_ne_bytes()
        );
        assert_eq!(&buf[16..20], &10u32.to_ne_bytes(), "vni");

        let parsed = TunnelMessage::parse(
            &TunnelMessageBuffer::new_checked(&buf).unwrap(),
        )
        .unwrap();
        assert_eq!(parsed.header.index, 2);
        assert_eq!(parsed.vnis, vec![10]);
    }
}
