## Requirements For A QUIC Transportable RPC Layer

The recent refactor makes `seastar::rpc::connection` consume an abstract `transport` (see `include/seastar/rpc/rpc.hh:248-314`). To swap TCP for QUIC without touching RPC logic we need a QUIC-facing API that can satisfy the same contract. This document lists the missing pieces and how they should look.

### 1. Connection life-cycle hooks

**Need:** a way to create a QUIC client/server session and hand an already handshaken byte stream to RPC.

**Proposed surface:**

```c++
namespace seastar::quic {

struct negotiated_stream {
    // a bidirectional QUIC stream ready for app data
    stream_id id;
    data_source source;   // wraps ngtcp2_conn_read_stream
    data_sink   sink;     // wraps ngtcp2_conn_write_stream
    socket_address peer;
    socket_address local;
    future<> close();     // graceful FIN / CONNECTION_CLOSE
};

class client_session {
public:
    future<negotiated_stream> connect(quic_client_config cfg);
    future<> stop();
};

class server_session {
public:
    future<> start(quic_server_config cfg);
    future<negotiated_stream> accept();  // returns when TLS+QUIC handshake finishes
    future<> stop();
};

}
```

This mirrors the existing TCP path: the RPC client calls `connect()` in the background, RPC server loops on `accept()`. Each call must return the stream plus final peer/local addresses (keep them updated when migration happens).

### 2. Stream → RPC bridging

`rpc::connection::transport` expects:

```c++
input_stream<char>& read_stream();
output_stream<char>& write_stream();
void shutdown_input();
void shutdown_output();
future<> close_write_stream();
```

So the QUIC API must expose a `data_source`/`data_sink` pair (or similar) that can be wrapped in Seastar `input_stream` / `output_stream`. Requirements:

* Reads yield contiguous buffers (`temporary_buffer<char>`). When ngtcp2 produces scattered IO, provide a helper that coalesces to `temporary_buffer`.
* Writes accept a `temporary_buffer<char>` or `std::vector<temporary_buffer<char>>`. A natural implementation is `data_sink::put()` calling `ngtcp2_conn_writev_stream`.
* `shutdown_input()` / `shutdown_output()` map to stream FIN / STOP_SENDING / CONNECTION_CLOSE.
* `close_write_stream()` returns a future that resolves when all pending data is flushed and FIN is acknowledged (needed for RPC stream closing semantics).

### 3. Error and timeout propagation

`rpc::connection` aborts outstanding RPCs when the transport reports an error. The QUIC layer should:

* Translate ngtcp2/gnutls error codes into exceptions (already done via `quic_error`).
* Surface them through `negotiated_stream::source` / `sink` (e.g., have `data_source::get()` and `data_sink::put()` fail with `quic_exception`).
* Provide an async hook to wait for drain/close so RPC can invoke it from `stop_send_loop()` without leaking packets.

Also, consider exposing an optional `wait_writable(deadline)` so RPC’s existing timeout handling can leverage QUIC pacing; otherwise the current wall-clock timers are still valid.

### 4. Peer/local metadata

RPC clients/servers call `peer_address()` / `local_address()` frequently. The transport must supply up-to-date addresses, especially because QUIC allows migration. Each `negotiated_stream` should therefore expose accessors returning the *current* tuple; if a migration occurs, update the stored addresses so RPC logging and metrics stay accurate.

### 5. Integration points

Once the API above exists:

1. Implement `class quic_transport final : public rpc::connection::transport` that wraps a `negotiated_stream`.
2. Add helpers for RPC clients and servers:
   ```c++
   std::unique_ptr<rpc::connection::transport>
   make_quic_client_transport(quic::negotiated_stream&&);

   std::unique_ptr<rpc::connection::transport>
   make_quic_server_transport(quic::negotiated_stream&&);
   ```
3. Extend `rpc::client_options` / `rpc::server_options` with a variant (`std::variant<tcp_config, quic_client_config>`), and switch `client::loop()` / `server::accept()` to either run the TCP path or call the QUIC factory before invoking `set_transport()`.

With these pieces in place, replacing TCP with QUIC becomes a configuration choice; RPC framing, handler logic, compression, etc., remain untouched.
