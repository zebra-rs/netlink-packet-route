// SPDX-License-Identifier: MIT

use anyhow::Context;
use netlink_packet_utils::{
    traits::{Emitable, Parseable, ParseableParametrized},
    DecodeError,
};

use super::{
    super::AddressFamily, NexthopAttribute, NexthopHeader, NexthopMessageBuffer,
};

#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[non_exhaustive]
pub struct NexthopMessage {
    pub header: NexthopHeader,
    pub attributes: Vec<NexthopAttribute>,
}

impl Emitable for NexthopMessage {
    fn buffer_len(&self) -> usize {
        self.header.buffer_len() + self.attributes.as_slice().buffer_len()
    }

    fn emit(&self, buffer: &mut [u8]) {
        self.header.emit(buffer);
        self.attributes
            .as_slice()
            .emit(&mut buffer[self.header.buffer_len()..]);
    }
}

impl<'a, T: AsRef<[u8]> + 'a> Parseable<NexthopMessageBuffer<&'a T>>
    for NexthopMessage
{
    fn parse(buf: &NexthopMessageBuffer<&'a T>) -> Result<Self, DecodeError> {
        let header = NexthopHeader::parse(buf)
            .context("failed to parse nexthop message header")?;
        let address_family = header.address_family;
        Ok(NexthopMessage {
            header,
            attributes: Vec::<NexthopAttribute>::parse_with_param(
                buf,
                address_family,
            )
            .context("failed to parse nexthop message NLAs")?,
        })
    }
}

impl<'a, T: AsRef<[u8]> + 'a>
    ParseableParametrized<NexthopMessageBuffer<&'a T>, AddressFamily>
    for Vec<NexthopAttribute>
{
    fn parse_with_param(
        buf: &NexthopMessageBuffer<&'a T>,
        address_family: AddressFamily,
    ) -> Result<Self, DecodeError> {
        let mut attributes = vec![];
        for nla_buf in buf.attributes() {
            attributes.push(NexthopAttribute::parse_with_param(
                &nla_buf?,
                address_family,
            )?);
        }
        Ok(attributes)
    }
}

#[cfg(test)]
mod tests {
    use crate::nexthop::{NexthopAttribute, NexthopGroup};
    use crate::RouteNetlinkMessage;
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload};

    // RTM_NEWNEXTHOP for a multipath group: id 15, members {2, 7}.
    // Regression test for parse_u32 being handed the full 8-byte
    // nexthop_grp entry, which made every group nexthop undecodable.
    #[test]
    fn decode_rtm_newnexthop_group() {
        let bytes: &[u8] = &[
            0x3c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x05, 0x05, 0x59, 0x00, 0x00,
            0x00, 0xff, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x06,
            0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x02, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let msg = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
            .expect("RTM_NEWNEXTHOP group must decode");
        let NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewNexthop(nh)) =
            msg.payload
        else {
            panic!("expected NewNexthop, got {:?}", msg.payload);
        };
        assert!(nh.attributes.contains(&NexthopAttribute::Id(15)));
        assert!(nh.attributes.iter().any(|a| matches!(
            a,
            NexthopAttribute::Group(g)
                if g == &vec![
                    NexthopGroup { id: 2, weight: 0, weight_high: 0, resvd2: 0 },
                    NexthopGroup { id: 7, weight: 0, weight_high: 0, resvd2: 0 },
                ]
        )));
    }
}
