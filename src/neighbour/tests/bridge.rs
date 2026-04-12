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
