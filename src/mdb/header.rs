// SPDX-License-Identifier: MIT

use netlink_packet_utils::{
    nla::{NlaBuffer, NlasIterator},
    DecodeError, Emitable,
};

use crate::AddressFamily;

const MDB_HEADER_LEN: usize = 8;

buffer!(MdbMessageBuffer(MDB_HEADER_LEN) {
    family: (u8, 0),
    _pad: (u8, 1),
    _pad2: (u16, 2..4),
    index: (u32, 4..8),
    payload: (slice, MDB_HEADER_LEN..)
});

impl<'a, T: AsRef<[u8]> + ?Sized> MdbMessageBuffer<&'a T> {
    pub fn nlas(
        &self,
    ) -> impl Iterator<Item = Result<NlaBuffer<&'a [u8]>, DecodeError>> {
        NlasIterator::new(self.payload())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MdbHeader {
    pub family: AddressFamily,
    pub index: u32,
}

impl Emitable for MdbHeader {
    fn buffer_len(&self) -> usize {
        MDB_HEADER_LEN
    }

    fn emit(&self, buffer: &mut [u8]) {
        let mut packet = MdbMessageBuffer::new(buffer);
        packet.set_family(self.family.into());
        packet.set_index(self.index);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdbState {
    Temporary,
    Permanent,
    Other(u8),
}

impl MdbState {
    pub fn new(value: u8) -> Self {
        match value {
            0 => Self::Temporary,
            1 => Self::Permanent,
            other => Self::Other(other),
        }
    }

    pub fn value(&self) -> u8 {
        match self {
            Self::Temporary => 0,
            Self::Permanent => 1,
            Self::Other(v) => *v,
        }
    }
}

impl Default for MdbState {
    fn default() -> Self {
        Self::Temporary
    }
}
