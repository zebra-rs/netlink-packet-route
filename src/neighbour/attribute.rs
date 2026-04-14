// SPDX-License-Identifier: MIT

use anyhow::Context;
use byteorder::{BigEndian, ByteOrder, NativeEndian};
use netlink_packet_utils::{
    nla::{DefaultNla, Nla, NlaBuffer},
    parsers::{parse_u16, parse_u16_be, parse_u32},
    DecodeError, Emitable, Parseable, ParseableParametrized,
};

use super::{NeighbourAddress, NeighbourCacheInfo, NeighbourCacheInfoBuffer};
use crate::{
    ip::{parse_ipv4_addr, parse_ipv6_addr},
    route::RouteProtocol,
    AddressFamily,
};
use netlink_packet_utils::nla::{NlasIterator, NLA_F_NESTED};
use netlink_packet_utils::parsers::parse_u8;

const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NDA_PROBES: u16 = 4;
const NDA_VLAN: u16 = 5;
const NDA_PORT: u16 = 6;
const NDA_VNI: u16 = 7;
const NDA_IFINDEX: u16 = 8;
// Kernel constant name is NDA_MASTER
const NDA_CONTROLLER: u16 = 9;
const NDA_LINK_NETNSID: u16 = 10;
const NDA_SRC_VNI: u16 = 11;
const NDA_PROTOCOL: u16 = 12;
const NDA_NH_ID: u16 = 13;
const NDA_FDB_EXT_ATTRS: u16 = 14;

// Nested attribute constants within NDA_FDB_EXT_ATTRS
const NFEA_ACTIVITY_NOTIFY: u16 = 1;
const NFEA_DONT_REFRESH: u16 = 2;

/// Extended FDB attributes (nested within NDA_FDB_EXT_ATTRS)
#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum FdbExtAttr {
    /// NFEA_ACTIVITY_NOTIFY — u8 flags for HW offload notification
    ActivityNotify(u8),
    /// NFEA_DONT_REFRESH — flag, zero-length, presence signals "don't refresh on traffic"
    DontRefresh,
    /// Unknown/other nested attribute
    Other(DefaultNla),
}

impl Nla for FdbExtAttr {
    fn value_len(&self) -> usize {
        match self {
            Self::ActivityNotify(_) => 1,
            Self::DontRefresh => 0,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::ActivityNotify(_) => NFEA_ACTIVITY_NOTIFY,
            Self::DontRefresh => NFEA_DONT_REFRESH,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::ActivityNotify(v) => buffer[0] = *v,
            Self::DontRefresh => {}
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>> for FdbExtAttr {
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NFEA_ACTIVITY_NOTIFY => Self::ActivityNotify(
                parse_u8(payload)
                    .context("invalid NFEA_ACTIVITY_NOTIFY value")?,
            ),
            NFEA_DONT_REFRESH => Self::DontRefresh,
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid NFEA value (unknown type)")?,
            ),
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum NeighbourAttribute {
    Destination(NeighbourAddress),
    LinkLocalAddress(Vec<u8>),
    CacheInfo(NeighbourCacheInfo),
    Probes(u32),
    Vlan(u16),
    Port(u16),
    Vni(u32),
    IfIndex(u32),
    Controller(u32),
    LinkNetNsId(u32),
    SourceVni(u32),
    Protocol(RouteProtocol),
    TunnelEndpoint(NeighbourAddress),
    NhId(u32),
    FdbExtAttrs(Vec<FdbExtAttr>),
    Other(DefaultNla),
}

impl Nla for NeighbourAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::LinkLocalAddress(bytes) => bytes.len(),
            Self::Destination(v) => v.buffer_len(),
            Self::TunnelEndpoint(v) => v.buffer_len(),
            Self::CacheInfo(v) => v.buffer_len(),
            Self::Vlan(_) | Self::Port(_) => 2,
            Self::Protocol(v) => v.buffer_len(),
            Self::Probes(_)
            | Self::LinkNetNsId(_)
            | Self::Controller(_)
            | Self::Vni(_)
            | Self::IfIndex(_)
            | Self::SourceVni(_)
            | Self::NhId(_) => 4,
            Self::FdbExtAttrs(attrs) => attrs.as_slice().buffer_len(),
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Destination(v) => v.emit(buffer),
            Self::TunnelEndpoint(v) => v.emit(buffer),
            Self::LinkLocalAddress(bytes) => {
                buffer.copy_from_slice(bytes.as_slice())
            }
            Self::CacheInfo(v) => v.emit(buffer),
            Self::Vlan(value) => NativeEndian::write_u16(buffer, *value),
            Self::Port(value) => BigEndian::write_u16(buffer, *value),
            Self::Probes(value)
            | Self::LinkNetNsId(value)
            | Self::Controller(value)
            | Self::Vni(value)
            | Self::IfIndex(value)
            | Self::SourceVni(value)
            | Self::NhId(value) => NativeEndian::write_u32(buffer, *value),
            Self::Protocol(v) => v.emit(buffer),
            Self::FdbExtAttrs(attrs) => attrs.as_slice().emit(buffer),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::Destination(_) => NDA_DST,
            Self::TunnelEndpoint(_) => NDA_DST,
            Self::LinkLocalAddress(_) => NDA_LLADDR,
            Self::CacheInfo(_) => NDA_CACHEINFO,
            Self::Probes(_) => NDA_PROBES,
            Self::Vlan(_) => NDA_VLAN,
            Self::Port(_) => NDA_PORT,
            Self::Vni(_) => NDA_VNI,
            Self::IfIndex(_) => NDA_IFINDEX,
            Self::Controller(_) => NDA_CONTROLLER,
            Self::LinkNetNsId(_) => NDA_LINK_NETNSID,
            Self::SourceVni(_) => NDA_SRC_VNI,
            Self::Protocol(_) => NDA_PROTOCOL,
            Self::NhId(_) => NDA_NH_ID,
            Self::FdbExtAttrs(_) => NDA_FDB_EXT_ATTRS | NLA_F_NESTED,
            Self::Other(nla) => nla.kind(),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized>
    ParseableParametrized<NlaBuffer<&'a T>, AddressFamily>
    for NeighbourAttribute
{
    fn parse_with_param(
        buf: &NlaBuffer<&'a T>,
        address_family: AddressFamily,
    ) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            NDA_DST => {
                // In AF_BRIDGE context (VXLAN FDB), NDA_DST is a tunnel endpoint IP
                // In other contexts (IP neighbors), it's a neighbor address
                if address_family == AddressFamily::Bridge {
                    // For tunnel endpoints in VXLAN FDB, detect address type from payload length
                    let addr = match payload.len() {
                        4 => {
                            let ipv4 = parse_ipv4_addr(payload).context(
                                "invalid tunnel endpoint IPv4 address",
                            )?;
                            NeighbourAddress::Inet(ipv4)
                        }
                        16 => {
                            let ipv6 = parse_ipv6_addr(payload).context(
                                "invalid tunnel endpoint IPv6 address",
                            )?;
                            NeighbourAddress::Inet6(ipv6)
                        }
                        _ => NeighbourAddress::Other(payload.to_vec()),
                    };
                    Self::TunnelEndpoint(addr)
                } else {
                    let addr = NeighbourAddress::parse_with_param(
                        address_family,
                        payload,
                    )
                    .context(format!("invalid NDA_DST value {:?}", payload))?;
                    Self::Destination(addr)
                }
            }
            NDA_LLADDR => Self::LinkLocalAddress(payload.to_vec()),
            NDA_CACHEINFO => Self::CacheInfo(
                NeighbourCacheInfo::parse(
                    &NeighbourCacheInfoBuffer::new_checked(payload).context(
                        format!("invalid NDA_CACHEINFO value {:?}", payload),
                    )?,
                )
                .context(format!(
                    "invalid NDA_CACHEINFO value {:?}",
                    payload
                ))?,
            ),
            NDA_PROBES => {
                Self::Probes(parse_u32(payload).context(format!(
                    "invalid NDA_PROBES value {:?}",
                    payload
                ))?)
            }
            NDA_VLAN => Self::Vlan(parse_u16(payload)?),
            NDA_PORT => Self::Port(
                parse_u16_be(payload)
                    .context(format!("invalid NDA_PORT value {payload:?}"))?,
            ),
            NDA_VNI => Self::Vni(parse_u32(payload)?),
            NDA_IFINDEX => Self::IfIndex(parse_u32(payload)?),
            NDA_CONTROLLER => Self::Controller(parse_u32(payload).context(
                format!("invalid NDA_CONTROLLER value {payload:?}"),
            )?),
            NDA_LINK_NETNSID => Self::LinkNetNsId(parse_u32(payload).context(
                format!("invalid NDA_LINK_NETNSID value {payload:?}"),
            )?),
            NDA_SRC_VNI => Self::SourceVni(parse_u32(payload)?),
            NDA_PROTOCOL => {
                Self::Protocol(RouteProtocol::parse(payload).context(
                    format!("invalid NDA_PROTOCOL value {:?}", payload),
                )?)
            }
            NDA_NH_ID => Self::NhId(
                parse_u32(payload)
                    .context(format!("invalid NDA_NH_ID value {payload:?}"))?,
            ),
            NDA_FDB_EXT_ATTRS => {
                let mut attrs = Vec::new();
                let err = "failed to parse NDA_FDB_EXT_ATTRS";
                for nla in NlasIterator::new(payload) {
                    let nla_buf = nla.context(err)?;
                    attrs.push(FdbExtAttr::parse(&nla_buf).context(err)?);
                }
                Self::FdbExtAttrs(attrs)
            }
            _ => Self::Other(
                DefaultNla::parse(buf)
                    .context("invalid link NLA value (unknown type)")?,
            ),
        })
    }
}
