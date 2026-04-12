// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    DecodeError, Emitable, Parseable, ParseableParametrized,
};

use super::{MdbAttribute, MdbHeader, MdbMessageBuffer};
use crate::AddressFamily;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MdbMessage {
    pub header: MdbHeader,
    pub attributes: Vec<MdbAttribute>,
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<MdbMessageBuffer<&'a T>>
    for MdbMessage
{
    fn parse(buf: &MdbMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let family = AddressFamily::from(buf.family());
        let index = buf.index();

        let header = MdbHeader { family, index };

        let mut attributes = vec![];
        for nla_buf in buf.nlas() {
            let nla = nla_buf?;
            attributes.push(MdbAttribute::parse_with_param(&nla, ())?);
        }

        Ok(MdbMessage { header, attributes })
    }
}

impl Emitable for MdbMessage {
    fn buffer_len(&self) -> usize {
        8 + self.attributes.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        buffer[0] = self.header.family.into();
        buffer[1..4].copy_from_slice(&[0u8; 3]);
        buffer[4..8].copy_from_slice(&self.header.index.to_ne_bytes());

        self.attributes.as_slice().emit(&mut buffer[8..]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mdb_message_roundtrip() {
        let msg = MdbMessage {
            header: MdbHeader {
                family: AddressFamily::Bridge,
                index: 3,
            },
            attributes: vec![],
        };

        let mut buffer = vec![0; msg.buffer_len()];
        msg.emit(&mut buffer);

        let parsed =
            MdbMessage::parse(&MdbMessageBuffer::new_checked(&buffer).unwrap())
                .unwrap();

        assert_eq!(parsed.header.family, msg.header.family);
        assert_eq!(parsed.header.index, msg.header.index);
    }
}
