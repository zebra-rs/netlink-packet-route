// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{NlaBuffer, NlasIterator},
    DecodeError, Emitable,
};

use crate::AddressFamily;

const TUNNEL_HEADER_LEN: usize = 8;

// `struct tunnel_msg` (linux/if_bridge.h): __u8 family; __u8 flags;
// __u16 reserved2; __u32 ifindex.
buffer!(TunnelMessageBuffer(TUNNEL_HEADER_LEN) {
    family: (u8, 0),
    flags: (u8, 1),
    _reserved2: (u16, 2..4),
    index: (u32, 4..8),
    payload: (slice, TUNNEL_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> TunnelMessageBuffer<&'a T> {
    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TunnelHeader {
    pub family: AddressFamily,
    pub flags: u8,
    pub index: u32,
}

impl Emitable for TunnelHeader {
    fn buffer_len(&self) -> usize {
        TUNNEL_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = TunnelMessageBuffer::new(buffer);
        packet.set_family(self.family.into());
        packet.set_flags(self.flags);
        packet.set_index(self.index);
    }
}
