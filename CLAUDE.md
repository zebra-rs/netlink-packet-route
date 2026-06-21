# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

- Build: `cargo build`
- Unit tests: `cargo test` (run a single test: `cargo test <test_name>` or `cargo test --test <file>`)
- Format check: `cargo fmt --all -- --check` (CI runs this on **nightly**)
- Lint: `cargo clippy -- -D warnings` (also nightly)
- Coverage (matches CI): `cargo llvm-cov --all-features --workspace --lcov --output-path lcov.info`
- Cross-target build matrix: `tools/test_cross_build.sh` — reads target list from `.github/workflows/build.yml` (currently x86_64 for linux-gnu, freebsd, fuchsia, apple-darwin, linux-android). Non-Linux targets use the fallback `AddressFamily`; Linux/Fuchsia and FreeBSD have their own modules.
- Run an example against the live kernel: `cargo run --example dump_packet_links` (others: `dump_rules`, `dump_neighbours`, `dump_neighbour_tables`, `dump_packet_link_bridge_vlan`, `new_rule`).

`rustfmt.toml` pins `max_width = 80` and `edition = "2021"`. CI enforces rustfmt/clippy and a SPDX license header on every non-ignored file (see `.licenserc.yaml`).

## Architecture

This crate is a **pure serializer/parser** for the Linux `rtnetlink` protocol (no sockets — users typically go through the `rtnetlink` crate). The public API is in `src/lib.rs` and the top-level `RouteNetlinkMessage` enum in `src/message.rs`.

### Top-level dispatch (`src/message.rs`)

`RouteNetlinkMessage` is a `#[non_exhaustive]` enum with one variant per `RTM_*` message type (NewLink/DelLink/GetLink/SetLink, NewAddress/..., NewRoute/..., rule, tc, nsid, nexthop, mdb, prefix, neighbour, neighbour_table). It implements `NetlinkSerializable` and `NetlinkDeserializable` from `netlink-packet-core`, so it plugs into that crate's `NetlinkMessage<T>` envelope. Parsing is via `ParseableParametrized<..., u16>` where the `u16` is the message type from the netlink header; the `message_type()` method is the inverse mapping. Note that several `RTM_GETXXX` paths include a **4-byte iproute2 compatibility hack**: when iproute2 sends a malformed GET with only the family byte + padding, we synthesize an empty message rather than erroring.

### Per-protocol module layout

Each protocol lives in its own module (`link/`, `address/`, `route/`, `rule/`, `tc/`, `neighbour/`, `neighbour_table/`, `nsid/`, `prefix/`, `nexthop/`, `mdb/`) and follows a consistent pattern:

- `mod.rs` — re-exports the public types. Internal details (e.g. `Vec…` wrappers used for parametrized parsing) are kept `pub(crate)` or private.
- `message.rs` — the `XxxMessage { header, attributes }` struct. Implements `Emitable` and `Parseable<XxxMessageBuffer>`. Some (e.g. `route`) use `ParseableParametrized` on the NLA vec to thread context like `AddressFamily` and `RouteType` down into attribute decoding (see `RTA_ENCAP_TYPE` two-pass parse in `src/route/message.rs`).
- `header.rs` — fixed-size header defined via the `buffer!` macro from `netlink-packet-utils` (declares an `XxxMessageBuffer` newtype over `&[u8]` with typed accessors and a `payload` slice holding the NLAs).
- `attribute.rs` — the `XxxAttribute` enum covering every NLA kind. Constants mirror the kernel `XXXA_*` / `IFLA_*` / `RTA_*` / `NDA_*` names. **Unknown attribute kinds must decode to `Other(DefaultNla)`, never error.** The enum implements `Nla` (emit) and `Parseable<NlaBuffer<&[u8]>>` (parse) — usually `ParseableParametrized` when attribute interpretation depends on header/context.
- `tests/` or `tests.rs` — unit tests verifying round-trip (parse then emit) against real `nlmon` captures stored as `Vec<u8>` literals.

Sub-enums / bitflags that model kernel constants (e.g. `LinkFlags`, `RouteFlags`, `RouteProtocol`, `RouteScope`, `RouteType`) live in their own files. Bitflags use the `bitflags` crate with `from_bits_retain` so unknown bits survive a round-trip.

### `AddressFamily` platform split

`src/address_family_{linux,freebsd,fallback}.rs` define platform-specific numeric constants. `src/lib.rs` selects one at compile time based on `target_os`. Parsers in `route/`, `address/`, etc. accept `AddressFamily` as a parametrized parse input — be careful that any new constant used in parsing is defined for all three variants, or that the code gracefully degrades on non-Linux targets (otherwise cross-builds in the CI matrix will fail).

### Large sub-trees

- `src/link/` — by far the largest. `link_info/` holds per-kind interface info (`InfoKind::Bond`, `Bridge`, `Vxlan`, `MacVlan`, `MacSec`, `Gre*`, `IpVlan`, `Vti`, `Xfrm`, `Vrf`, `Hsr`, …); `af_spec/` holds `AfSpecInet/Inet6/Bridge/Unspec` with inet6 stats/devconf; `sriov/` models `IFLA_VFINFO_LIST`; `proto_info/` handles bridge/inet6 `IFLA_PROTINFO`.
- `src/tc/` — split into `qdiscs/`, `filters/`, `actions/`, `stats/`, `options.rs`. `TODO.md` notes tc still has unparsed `Vec<u8>` holes; prefer typed decoding but falling back to `Other(DefaultNla)` is acceptable.
- `src/route/` — includes MPLS, seg6/seg6local (SRv6), multipath next-hops, lightweight tunnel encapsulation (`RTA_ENCAP`/`RTA_ENCAP_TYPE`).

### Trait contract (from `netlink-packet-utils`)

Every type in the public API ultimately implements:

- `Emitable` — `buffer_len()` + `emit(&mut [u8])` — serializes into a pre-sized buffer. `buffer_len()` must match exactly what `emit` writes; mismatches cause panics or corrupted packets.
- `Parseable<Buffer>` or `ParseableParametrized<Buffer, Ctx>` — deserializes. Returns `Result<_, DecodeError>`.
- `Nla` (for attribute enums) — `value_len()`, `kind()`, `emit_value()`.

When adding a new attribute, touch all three impls plus the parse match arm, and add a unit test with a real capture.

## Contribution rules (from README.md)

- **No `unwrap()` / `expect()` / panics** in library code — always return `Result`.
- Every new source file starts with `// SPDX-License-Identifier: MIT`.
- All public structs and enums are `#[non_exhaustive]` unless a maintainer grants an exception.
- Unknown netlink attributes decode to `Other(DefaultNla)` — never break parsing on an unknown kind.
- Integration tests that talk to the real kernel belong in the `rtnetlink` crate, not here. This crate is unit-test only.
- Capture test fixtures with `modprobe nlmon; ip link add nl0 type nlmon; ip link set nl0 up; tcpdump -i nl0 -w capture.cap`, then Wireshark → right-click → "Copy as Hex Dump". `https://github.com/cathay4t/hex_to_rust` converts the dump to a `Vec<u8>` literal.
- For messages not observable via nlmon, use `Debug` output and annotate each byte in a comment.
- Commits must have a `Signed-off-by` trailer (`git commit --signoff`).
