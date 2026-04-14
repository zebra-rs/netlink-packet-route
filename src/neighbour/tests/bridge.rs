// SPDX-License-Identifier: MIT

use std::net::Ipv4Addr;

use netlink_packet_utils::{Emitable, Parseable};

use crate::{
    neighbour::{
        flags::NeighbourFlags, NeighbourAddress, NeighbourAttribute,
        NeighbourHeader, NeighbourMessage, NeighbourMessageBuffer,
        NeighbourState,
    },
    route::RouteType,
    AddressFamily,
};

// wireshark capture(netlink message header removed) of nlmon against command:
//   ip -f bridge neighbour show
#[test]
fn test_bridge_neighbour_show() {
    let raw = vec![
        0x07, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x80, 0x00, 0x02, 0x00,
        0x0a, 0x00, 0x02, 0x00, 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01, 0x00, 0x00,
    ];

    let expected = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 3,
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Own,
            kind: RouteType::Unspec,
        },
        attributes: vec![NeighbourAttribute::LinkLocalAddress(vec![
            1, 0, 94, 0, 0, 1,
        ])],
    };

    assert_eq!(
        expected,
        NeighbourMessage::parse(&NeighbourMessageBuffer::new(&raw)).unwrap()
    );

    let mut buf = vec![0; expected.buffer_len()];

    expected.emit(&mut buf);

    assert_eq!(buf, raw);
}

// Test VXLAN FDB entry with tunnel endpoint (remote VTEP) IP address
#[test]
fn test_vxlan_fdb_with_tunnel_endpoint_ipv4() {
    // Construct a VXLAN FDB entry with tunnel endpoint
    let tunnel_endpoint_ip = Ipv4Addr::new(10, 0, 0, 2);

    let msg = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 3, // vxlan0
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Own, // NTF_SELF
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::LinkLocalAddress(vec![
                0, 0x11, 0x22, 0x33, 0x44, 0x55,
            ]),
            NeighbourAttribute::Vni(100),
            NeighbourAttribute::SourceVni(100),
            NeighbourAttribute::Port(4789),
            NeighbourAttribute::TunnelEndpoint(NeighbourAddress::Inet(
                tunnel_endpoint_ip,
            )),
        ],
    };

    // Test roundtrip: emit -> parse
    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    let parsed = NeighbourMessage::parse(
        &NeighbourMessageBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();

    // Verify header is preserved
    assert_eq!(parsed.header.family, msg.header.family);
    assert_eq!(parsed.header.ifindex, msg.header.ifindex);

    // Verify required attributes are present
    assert!(parsed.attributes.iter().any(|attr| {
        matches!(attr, NeighbourAttribute::LinkLocalAddress(mac) if mac == &vec![0, 0x11, 0x22, 0x33, 0x44, 0x55])
    }));
    assert!(parsed
        .attributes
        .iter()
        .any(|attr| matches!(attr, NeighbourAttribute::Vni(100))));
    assert!(parsed
        .attributes
        .iter()
        .any(|attr| matches!(attr, NeighbourAttribute::SourceVni(100))));
    assert!(parsed
        .attributes
        .iter()
        .any(|attr| matches!(attr, NeighbourAttribute::Port(4789))));

    // Verify that TunnelEndpoint is correctly parsed in AF_BRIDGE context
    let has_tunnel_endpoint = parsed.attributes.iter().any(|attr| {
        if let NeighbourAttribute::TunnelEndpoint(NeighbourAddress::Inet(ip)) =
            attr
        {
            *ip == tunnel_endpoint_ip
        } else {
            false
        }
    });
    assert!(
        has_tunnel_endpoint,
        "TunnelEndpoint with correct IP not found"
    );
}

// Test that NDA_DST is interpreted as TunnelEndpoint in AF_BRIDGE context
#[test]
fn test_tunnel_endpoint_parsing_in_bridge_context() {
    let tunnel_endpoint_ip = Ipv4Addr::new(192, 168, 1, 100);

    let msg = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 5,
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Own,
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::LinkLocalAddress(vec![
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ]),
            NeighbourAttribute::TunnelEndpoint(NeighbourAddress::Inet(
                tunnel_endpoint_ip,
            )),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    let parsed = NeighbourMessage::parse(
        &NeighbourMessageBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();

    // The message should round-trip correctly
    assert_eq!(parsed.attributes.len(), msg.attributes.len());

    // Check that we have a TunnelEndpoint attribute
    let has_tunnel_endpoint = parsed
        .attributes
        .iter()
        .any(|attr| matches!(attr, NeighbourAttribute::TunnelEndpoint(_)));
    assert!(has_tunnel_endpoint, "TunnelEndpoint attribute not found");
}

// Test FdbExtAttr::ActivityNotify roundtrip
#[test]
fn test_fdb_ext_attr_activity_notify_roundtrip() {
    use crate::neighbour::FdbExtAttr;

    let msg = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 3,
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Own,
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::LinkLocalAddress(vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ]),
            NeighbourAttribute::Vni(100),
            NeighbourAttribute::TunnelEndpoint(NeighbourAddress::Inet(
                Ipv4Addr::new(10, 0, 0, 2),
            )),
            NeighbourAttribute::FdbExtAttrs(vec![FdbExtAttr::ActivityNotify(
                0x01,
            )]),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    let parsed = NeighbourMessage::parse(
        &NeighbourMessageBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();

    // Verify FdbExtAttrs are present and correct
    let has_activity_notify = parsed.attributes.iter().any(|attr| {
        if let NeighbourAttribute::FdbExtAttrs(attrs) = attr {
            attrs.iter().any(|ext_attr| {
                matches!(ext_attr, FdbExtAttr::ActivityNotify(0x01))
            })
        } else {
            false
        }
    });
    assert!(has_activity_notify, "ActivityNotify attribute not found");
}

// Test FdbExtAttr::DontRefresh roundtrip
#[test]
fn test_fdb_ext_attr_dont_refresh_roundtrip() {
    use crate::neighbour::FdbExtAttr;

    let msg = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 3,
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Own,
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::LinkLocalAddress(vec![
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            ]),
            NeighbourAttribute::Vni(200),
            NeighbourAttribute::TunnelEndpoint(NeighbourAddress::Inet(
                Ipv4Addr::new(192, 168, 1, 50),
            )),
            // NFEA_DONT_REFRESH: BGP-learned remote VTEP MACs must not be refreshed
            NeighbourAttribute::FdbExtAttrs(vec![FdbExtAttr::DontRefresh]),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    let parsed = NeighbourMessage::parse(
        &NeighbourMessageBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();

    // Verify DontRefresh flag is present
    let has_dont_refresh = parsed.attributes.iter().any(|attr| {
        if let NeighbourAttribute::FdbExtAttrs(attrs) = attr {
            attrs
                .iter()
                .any(|ext_attr| matches!(ext_attr, FdbExtAttr::DontRefresh))
        } else {
            false
        }
    });
    assert!(has_dont_refresh, "DontRefresh attribute not found");
}

// Test multiple FdbExtAttrs in single NDA_FDB_EXT_ATTRS
#[test]
fn test_fdb_ext_attrs_multiple() {
    use crate::neighbour::FdbExtAttr;

    let msg = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 4,
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Own,
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::LinkLocalAddress(vec![
                0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            ]),
            NeighbourAttribute::Vni(300),
            NeighbourAttribute::TunnelEndpoint(NeighbourAddress::Inet(
                Ipv4Addr::new(172, 16, 0, 100),
            )),
            // Multiple extended FDB attributes
            NeighbourAttribute::FdbExtAttrs(vec![
                FdbExtAttr::ActivityNotify(0x02),
                FdbExtAttr::DontRefresh,
            ]),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    let parsed = NeighbourMessage::parse(
        &NeighbourMessageBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();

    // Verify both attributes are present
    let fdb_ext_attrs = parsed.attributes.iter().find_map(|attr| {
        if let NeighbourAttribute::FdbExtAttrs(attrs) = attr {
            Some(attrs)
        } else {
            None
        }
    });
    assert!(fdb_ext_attrs.is_some(), "FdbExtAttrs not found");

    let attrs = fdb_ext_attrs.unwrap();
    assert_eq!(attrs.len(), 2, "Expected 2 extended FDB attributes");

    let has_activity_notify = attrs
        .iter()
        .any(|attr| matches!(attr, FdbExtAttr::ActivityNotify(0x02)));
    let has_dont_refresh = attrs
        .iter()
        .any(|attr| matches!(attr, FdbExtAttr::DontRefresh));

    assert!(has_activity_notify, "ActivityNotify attribute not found");
    assert!(has_dont_refresh, "DontRefresh attribute not found");
}

// Test NhId attribute
#[test]
fn test_nh_id_roundtrip() {
    let msg = NeighbourMessage {
        header: NeighbourHeader {
            family: AddressFamily::Bridge,
            ifindex: 3,
            state: NeighbourState::Permanent,
            flags: NeighbourFlags::Own,
            kind: RouteType::Unspec,
        },
        attributes: vec![
            NeighbourAttribute::LinkLocalAddress(vec![
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            ]),
            NeighbourAttribute::Vni(100),
            NeighbourAttribute::TunnelEndpoint(NeighbourAddress::Inet(
                Ipv4Addr::new(10, 0, 0, 2),
            )),
            // NDA_NH_ID for ECMP nexthop groups (Phase 5)
            NeighbourAttribute::NhId(1000),
        ],
    };

    let mut buffer = vec![0; msg.buffer_len()];
    msg.emit(&mut buffer);

    let parsed = NeighbourMessage::parse(
        &NeighbourMessageBuffer::new_checked(&buffer).unwrap(),
    )
    .unwrap();

    // Verify NhId is present and correct
    let has_nh_id = parsed
        .attributes
        .iter()
        .any(|attr| matches!(attr, NeighbourAttribute::NhId(1000)));
    assert!(has_nh_id, "NhId attribute not found");
}
