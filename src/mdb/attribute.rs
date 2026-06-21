// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    DecodeError, ParseableParametrized,
};

const MDBA_MDB: u16 = 1;
const MDBA_MROUTE: u16 = 2;
const MDBA_MDB_EATTR: u16 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MdbAttribute {
    /// Multicast database entry (MDB table)
    MdbEntry(Vec<u8>),
    /// Multicast route entry
    MrouteEntry(Vec<u8>),
    /// Extended MDB attributes
    MdbExtAttrs(Vec<u8>),
    /// Unknown/other attribute
    Other(DefaultNla),
}

impl Nla for MdbAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::MdbEntry(v) | Self::MrouteEntry(v) | Self::MdbExtAttrs(v) => {
                v.len()
            }
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::MdbEntry(v) | Self::MrouteEntry(v) | Self::MdbExtAttrs(v) => {
                buffer.copy_from_slice(v.as_slice())
            }
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::MdbEntry(_) => MDBA_MDB,
            Self::MrouteEntry(_) => MDBA_MROUTE,
            Self::MdbExtAttrs(_) => MDBA_MDB_EATTR,
            Self::Other(attr) => attr.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ParseableParametrized<NlaBuffer<&'a T>, ()>
    for MdbAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        _param: (),
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MDBA_MDB => Self::MdbEntry(payload.to_vec()),
            MDBA_MROUTE => Self::MrouteEntry(payload.to_vec()),
            MDBA_MDB_EATTR => Self::MdbExtAttrs(payload.to_vec()),
            _ => Self::Other(DefaultNla::new(buf.kind(), payload.to_vec())),
        })
    }
}
