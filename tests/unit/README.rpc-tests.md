# RPC unit tests (TCP loopback & QUIC)

Two parallel suites run the **same** `seastar::rpc::protocol` test cases over two
transports, differing only in how client/server are wired:

| Suite      | Transport           | Test TU            | Shared body                | ctest name              |
|------------|---------------------|--------------------|----------------------------|-------------------------|
| `rpc_tcp`  | TCP loopback        | `rpc_tcp_test.cc`  | `rpc_test_body_tcp.inc.hh` | `Seastar.unit.rpc_tcp`  |
| `rpc_quic` | QUIC (ngtcp2 + TLS) | `rpc_quic_test.cc` | `rpc_test_body.inc.hh`     | `Seastar.unit.rpc_quic` |

`rpc_tcp` drives the in-process `loopback_socket`, so it exercises the protocol
logic with no real network/TLS. `rpc_quic` runs the same cases end-to-end against
a real QUIC server. Both failing points to the protocol; only `rpc_quic` failing
points to the QUIC transport. (Distinct from the upstream `rpc` suite,
`rpc_test.cc`, which covers the full sharded stack.)

## Run

```sh
ninja -C build/dev test_unit_rpc_tcp test_unit_rpc_quic
ctest --test-dir build/dev -R 'Seastar.unit.rpc_(tcp|quic)' --output-on-failure
```

`rpc_quic` additionally links `Boost::filesystem` and `DEPENDS testcrt` (builds
the test certs next to the executable); it listens on `127.0.0.1:52000+`.
