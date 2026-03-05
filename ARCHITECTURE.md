# Quinn (`quinn-schc`) Architecture and Execution Guide

This document explains how this repository is structured and how packets/data move through the system.

## 1) Repository topology

This workspace is split into layered crates:

- `quinn` - high-level async API and runtime integration (Tokio/Smol).
- `quinn-proto` - deterministic QUIC state machines and protocol logic (no socket I/O).
- `quinn-udp` - UDP socket specialization for ECN, GSO/GRO, pktinfo, no-fragment behavior.
- `bench`, `perf`, `fuzz` - benchmarks/perf harnesses/fuzzing.
- `docs/book` - user guide chapters and examples.

Top-level workspace membership is declared in `Cargo.toml`.

## 2) Layered architecture model

Think of Quinn as three layers:

1. **API/runtime layer (`quinn`)**
   - Public handles like `Endpoint`, `Connection`, `SendStream`, `RecvStream`.
   - Owns async tasks/drivers and socket polling loops.
   - Converts async operations into events consumed by `quinn-proto`.
2. **Protocol core (`quinn-proto`)**
   - `Endpoint` routes incoming datagrams, creates/owns protocol connections, tracks CIDs/tokens.
   - `Connection` owns handshake state, packet spaces, stream state, loss detection, congestion, timers.
   - Exposes polling-style interface: caller feeds events and drains outputs.
3. **UDP capability layer (`quinn-udp`)**
   - Platform-specific socket behavior (`unix.rs`, `windows.rs`, `fallback.rs`).
   - Provides metadata (`RecvMeta`) and batched transmit/receive support.

## 3) Crate responsibilities in detail

## 3.1 `quinn` (async orchestration + public API)

Entry module: `quinn/src/lib.rs`

- Re-exports most protocol/config types from `quinn-proto`.
- Defines async-facing runtime traits in `quinn/src/runtime/mod.rs`:
  - `Runtime`, `AsyncTimer`, `AsyncUdpSocket`, `UdpSender`.
- Provides concrete runtime adapters:
  - `runtime/tokio.rs`
  - `runtime/smol.rs`

Core orchestrators:

- `Endpoint` (`quinn/src/endpoint.rs`): API handle over a single UDP socket.
- `EndpointDriver`: async future that pumps receive path + cross-task events.
- `Connection` (`quinn/src/connection.rs`): API handle to one QUIC connection.
- `ConnectionDriver`: async future that drives one protocol connection.

Public stream/data interfaces:

- `SendStream` (`send_stream.rs`) - flow-controlled writes.
- `RecvStream` (`recv_stream.rs`) - ordered/unordered reads.
- Datagram API exposed via `Connection::{send_datagram, read_datagram}`.

Incoming acceptance controls:

- `Incoming` (`incoming.rs`) supports `accept`, `accept_with`, `refuse`, `retry`, `ignore`.

## 3.2 `quinn-proto` (sans-IO protocol state machines)

Entry module: `quinn-proto/src/lib.rs`

- `Endpoint` (`endpoint.rs`):
  - No I/O; consumes decoded datagrams via `handle(...)`.
  - Emits `DatagramEvent`:
    - `ConnectionEvent`
    - `NewConnection(Incoming)`
    - `Response(Transmit)`
- `Connection` (`connection/mod.rs`):
  - Owns stream/datagram state, packet spaces (Initial/Handshake/Data), timers, congestion/loss.
  - API shape is explicit event loop style:
    - feed inputs (`handle_event`, `handle_timeout`, stream operations)
    - drain outputs (`poll_transmit`, `poll_timeout`, `poll_endpoint_events`, `poll`)

Cross-component event types are in `shared.rs`:

- Endpoint -> connection: `ConnectionEvent`
- Connection -> endpoint: `EndpointEvent`

Protocol subsystems (mostly under `connection/`):

- Stream machinery (`connection/streams/*`)
- Datagram extension (`connection/datagrams.rs`)
- Loss detection/timers (`spaces.rs`, `timer.rs`)
- PMTU + pacing (`mtud.rs`, `pacing.rs`)
- Packet assembly/protection (`packet_builder.rs`, `packet_crypto.rs`)
- Congestion controllers (`congestion.rs`, `congestion/{new_reno,cubic,bbr}`)
- Transport parameter negotiation (`transport_parameters.rs`)
- Crypto abstraction and rustls-backed implementation (`crypto.rs`, `crypto/rustls.rs`)

## 3.3 `quinn-udp` (platform UDP behavior)

Entry module: `quinn-udp/src/lib.rs`

Provides shared wire metadata/types:

- `RecvMeta` (src addr, length/stride, ECN, dst_ip, interface index)
- `Transmit` (dest addr, payload, optional ECN/src_ip/segment_size)

Platform implementations:

- `unix.rs` - recvmsg/sendmsg paths, ECN control messages, GRO/GSO, fragmentation controls.
- `windows.rs` - Winsock-specific control message paths; ECN support is best-effort.
- `fallback.rs` - minimum-capability path (no advanced kernel features).

## 4) End-to-end receive path (packet ingress)

This is the most important control flow:

1. `EndpointDriver::poll` (`quinn/src/endpoint.rs`) calls `State::drive_recv`.
2. `drive_recv` calls `RecvState::poll_socket`, which reads UDP batches from `AsyncUdpSocket`.
3. For each datagram segment, `RecvState::poll_socket` calls `quinn_proto::Endpoint::handle(...)`.
4. `quinn-proto::Endpoint::handle` partially decodes the packet (`packet::PartialDecode`) and routes:
   - existing connection -> `DatagramEvent::ConnectionEvent`
   - new Initial -> `DatagramEvent::NewConnection`
   - direct endpoint response (version negotiation/stateless reset/close) -> `DatagramEvent::Response`
5. `quinn` handles each event:
   - New incoming stored in endpoint queue (`Endpoint::accept().await` consumes it).
   - Connection event sent on that connection's mpsc channel.
   - Response transmitted immediately through `UdpSender`.

Important property: `quinn-proto` decides protocol routing and validity, while `quinn` decides async scheduling and I/O execution.

## 5) End-to-end transmit path (packet egress)

1. App performs an operation on `Connection`/`SendStream`/`RecvStream` (open stream, write, reset, datagram send, etc.).
2. Operation mutates `quinn-proto::Connection` state through wrapped calls and wakes driver.
3. `ConnectionDriver::poll` executes:
   - processes queued connection events
   - calls `drive_transmit` to drain `poll_transmit(...)` from proto
4. `quinn-proto::Connection::poll_transmit` constructs protected QUIC packets:
   - packet space handling (Initial/Handshake/1-RTT)
   - ACK/loss probe behavior
   - anti-amplification checks
   - congestion + pacing checks
   - optional coalescing/GSO segmentation
5. `quinn` converts proto `Transmit` -> `quinn-udp::Transmit` and sends via `UdpSender::poll_send`.

## 6) Connection lifecycle

## 6.1 Client side

1. App calls `Endpoint::connect` / `connect_with` (`quinn/src/endpoint.rs`).
2. `quinn-proto::Endpoint::connect` allocates handle/CIDs, creates proto `Connection`, starts TLS session.
3. `Connecting` is returned (`quinn/src/connection.rs`) and resolves when handshake succeeds/fails.
4. Connection driver task is spawned at creation time and keeps protocol making progress.

## 6.2 Server side

1. App awaits `Endpoint::accept()`.
2. Under the hood, incoming Initials produce `proto::Incoming`.
3. App chooses policy using `Incoming`:
   - `accept` / `accept_with`
   - `retry` (address validation)
   - `refuse`
   - `ignore`
4. Accepted incoming becomes active connection with its own driver.

## 7) API-to-protocol mapping

- `Endpoint` methods mostly coordinate with `quinn-proto::Endpoint` and connection sets.
- `Connection` methods lock internal state, call proto-level operations, then wake driver.
- `SendStream`/`RecvStream` are thin wrappers over proto stream state:
  - async methods are implemented as poll loops with cancel-safety semantics documented per method.

Concurrency model (important):

- Endpoint and each connection have distinct driver futures.
- Cross-driver signaling uses mpsc channels + `Notify`.
- Shared mutable state is synchronized by mutexes inside `quinn`.

## 8) Timers, loss, pacing, congestion

`quinn-proto::Connection` owns timer table and loss recovery logic:

- `poll_timeout` exposes next deadline.
- timeout handling and packet ACK/loss processing mutate congestion state.
- controller interface in `congestion.rs` supports pluggable algorithms.
- built-in factories/controllers include NewReno, CUBIC, BBR.

Pacing/congestion decisions directly gate `poll_transmit`, so transport behavior is centralized in proto.

## 9) Configuration and negotiation

Main config surfaces:

- Endpoint-level: `EndpointConfig` (`quinn-proto/src/config/mod.rs`)
  - reset key, CID generator factory, supported versions, QUIC bit greasing, etc.
- Server/client: `ServerConfig`, `ClientConfig`
- Transport-level: `TransportConfig` (`quinn-proto/src/config/transport.rs`)
  - stream limits/windows
  - idle timeout
  - MTU discovery/padding
  - ack-frequency config
  - datagram buffering
  - congestion controller factory

Negotiation:

- `TransportParameters` are built/validated during handshake (`transport_parameters.rs`).
- Crypto abstraction is trait-based in `crypto.rs`, with rustls-backed implementation in `crypto/rustls.rs`.

### SCHC integration points (this fork)

- Capability is negotiated via private transport parameters in `quinn-proto/src/transport_parameters.rs` (`SchcVersion`, `SchcProfileId`).
- Local controls live in `TransportConfig` (`schc_enabled`, `schc_profile_id`, `schc_max_decompressed_payload`).
- Negotiated state is applied in `Connection::set_peer_params`.
- Compression/decompression hooks live at Data-space payload boundaries:
  - TX: `connection/packet_builder.rs` before packet protection.
  - RX: `connection/mod.rs::process_payload` after decryption and before frame iteration.
- Initial/Handshake payloads are not SCHC-compressed; 0-RTT payload processing remains non-SCHC.

## 10) Platform behavior notes

- QUIC efficiency depends heavily on UDP socket capabilities; this is why `quinn-udp` exists separately.
- Windows implementation explicitly handles environments where ECN socket options are unsupported.
- Fallback path preserves correctness with reduced performance/telemetry features.
- `Endpoint::new_with_abstract_socket` allows integrating custom socket/runtime stacks.

## 11) How to read the code quickly

Suggested reading order:

1. `README.md` (workspace overview)
2. `quinn/src/lib.rs` (public exports and high-level concepts)
3. `quinn/src/endpoint.rs` (endpoint driver + recv path)
4. `quinn/src/connection.rs` (connection driver + public operations)
5. `quinn-proto/src/endpoint.rs` (routing and incoming handling)
6. `quinn-proto/src/connection/mod.rs` (core protocol machine)
7. `quinn-udp/src/lib.rs` + `unix.rs`/`windows.rs` (I/O capabilities)
8. `quinn/examples/{server,client,connection}.rs` (usage patterns)

## 12) Testing and validation surfaces

- `quinn/src/tests.rs` contains integration-style runtime tests.
- `fuzz/` targets robustness of proto decoding/state transitions.
- `bench/` and `perf/` provide performance-focused harnesses.

For behavior changes, the safest verification is to run relevant crate tests and at least one example flow.

