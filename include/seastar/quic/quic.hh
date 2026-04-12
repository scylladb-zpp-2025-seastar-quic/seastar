/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/*
 * Copyright (C) 2026 ScyllaDB Ltd.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>

#include <seastar/core/future.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sstring.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/net/api.hh>
#include <seastar/quic/quic_error.hh>

namespace seastar::quic::experimental {

using stream_id = int64_t;
using application_error_code = uint64_t;
inline constexpr stream_id invalid_stream_id = -1;

enum class stream_type : uint8_t {
    bidirectional,
    unidirectional,
};

enum class congestion_control_algorithm : uint8_t {
    cubic,
    reno,
    bbr,
};

struct transport_config {
    uint64_t max_idle_timeout_ns = 60ULL * 1000 * 1000 * 1000;
    uint64_t initial_max_stream_data_bidi_local = 256 * 1024;
    uint64_t initial_max_stream_data_bidi_remote = 256 * 1024;
    uint64_t initial_max_stream_data_uni = 256 * 1024;
    uint64_t initial_max_data = 4 * 1024 * 1024;
    uint64_t initial_max_streams_bidi = 128;
    uint64_t initial_max_streams_uni = 128;
    uint64_t max_window = 0;
    uint64_t max_stream_window = 0;
    size_t ack_thresh = 2;
    uint64_t initial_rtt_ns = 0; // 0 = use ngtcp2 default (333ms)
    congestion_control_algorithm congestion_control = congestion_control_algorithm::cubic;
    size_t max_udp_payload_size = 65527;
    size_t max_tx_udp_payload_size = 1452;
    bool disable_tx_udp_payload_size_shaping = false;
};

struct connection_options {
    size_t max_pending_send_bytes = 4 * 1024 * 1024;
    size_t max_pending_receive_bytes = 4 * 1024 * 1024;
    transport_config transport{};
};

struct stream_open_options {
    stream_type type = stream_type::bidirectional;
};

namespace internal {
class session_runtime;
class stream_state;
class connection_engine;
using session_runtime_ptr = shared_ptr<session_runtime>;
using stream_state_ptr = shared_ptr<stream_state>;
using connection_engine_ptr = shared_ptr<connection_engine>;
}

class stream final {
public:
    stream();
    ~stream();

    stream(stream&&) noexcept;
    stream& operator=(stream&&) noexcept;

    stream(const stream&) = delete;
    stream& operator=(const stream&) = delete;

    bool is_open() const noexcept;
    stream_id id() const noexcept;
    stream_type type() const noexcept;
    bool can_read() const noexcept;
    bool can_write() const noexcept;

    input_stream<char> input(connected_socket_input_stream_config cfg = {});
    output_stream<char> output(size_t buffer_size = 8192);

    future<> close_output();
    future<> reset(application_error_code app_error_code = 0);
    future<> stop_sending(application_error_code app_error_code = 0);
    future<> wait_input_shutdown();

private:
    explicit stream(internal::stream_state_ptr state);

    internal::stream_state_ptr _state;

    friend class connection;
    friend class internal::connection_engine;
    friend connected_socket to_connected_socket(stream&& s);
};

class connection final {
public:
    connection();
    ~connection();

    connection(connection&&) noexcept;
    connection& operator=(connection&&) noexcept;

    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;

    bool is_open() const noexcept;
    socket_address local_address() const;
    socket_address peer_address() const;
    sstring selected_alpn() const;

    future<stream> open_stream(stream_open_options options = {});
    future<stream> accept_stream();
    future<> close();

private:
    explicit connection(internal::connection_engine_ptr state);

    internal::connection_engine_ptr _state;

    friend class quic_client;
    friend class quic_server;
};

connected_socket to_connected_socket(stream&& s);

namespace internal {

struct quic_message {
    stream_id stream = invalid_stream_id;
    temporary_buffer<char> payload;
    bool fin = false;
};

enum class stream_shutdown_side : uint8_t {
    read,
    write,
};

struct transport_command {
    enum class kind : uint8_t {
        send,
        open_stream,
        reset_stream,
        stop_sending,
        close_connection,
    };

    kind op = kind::send;
    quic_message msg;
    stream_type type = stream_type::bidirectional;
    application_error_code app_error_code = 0;
    std::shared_ptr<promise<stream_id>> open_result;
};

struct blocked_send_state {
    quic_message msg;
    size_t offset = 0;
    bool send_fin = false;
};

class session_runtime {
public:
    virtual ~session_runtime() = default;

    virtual bool is_open() const noexcept = 0;
    virtual socket_address local_address() const = 0;
    virtual socket_address peer_address() const = 0;
    virtual sstring selected_alpn() const = 0;

    virtual future<> send(quic_message msg) = 0;
    virtual future<stream_id> open_stream(stream_type type) = 0;
    virtual future<> reset_stream(stream_id sid, application_error_code app_error_code) = 0;
    virtual future<> stop_sending(stream_id sid, application_error_code app_error_code) = 0;
    virtual future<> close() = 0;

    virtual bool has_pending_commands() const noexcept = 0;
    virtual std::optional<transport_command> poll_command() = 0;
    virtual void set_command_notifier(std::function<void()> notifier) = 0;
    virtual void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) = 0;
    virtual void fail_open_stream(std::shared_ptr<promise<stream_id>> result, quic_error error, sstring detail) = 0;
    virtual void mark_transport_ready(socket_address local, socket_address peer, sstring selected_alpn) = 0;
    virtual void mark_transport_closed() = 0;
    virtual void mark_error(quic_error error, sstring detail) = 0;
};

struct transport_stream_write_result {
    int64_t nwrite = 0;
    size_t consumed = 0;
};

struct transport_open_stream_result {
    int rv = 0;
    stream_id sid = invalid_stream_id;
};

struct transport_debug_stats {
    uint64_t negotiated_tx_payload_limit = 0;
    uint64_t tx_packets = 0;
    uint64_t tx_bytes = 0;
    uint64_t tx_copy_bytes = 0;
    uint64_t tx_copy_events = 0;
    uint64_t tx_blocked_events = 0;
    uint64_t tx_zero_write_events = 0;
    uint64_t tx_packet_buffer_allocations = 0;
    uint64_t tx_packet_buffer_reuses = 0;
    uint64_t tx_packet_buffer_recycles = 0;
    uint64_t rx_packets = 0;
    uint64_t rx_bytes = 0;
    uint64_t rx_linearized_packets = 0;
    uint64_t rx_linearized_bytes = 0;
    uint64_t rx_fallback_copy_events = 0;
    uint64_t rx_fallback_copy_bytes = 0;
};

class connection_transport {
public:
    virtual ~connection_transport() = default;

    virtual bool transport_active() const noexcept = 0;
    virtual bool has_transport_connection() const noexcept = 0;
    virtual bool can_retry_blocked_open_streams() const noexcept = 0;
    virtual size_t tx_payload_limit_bytes() const noexcept = 0;
    virtual transport_debug_stats& debug_stats() noexcept = 0;

    virtual temporary_buffer<char> acquire_tx_packet_buffer() = 0;
    virtual int64_t write_pending_packet(uint8_t* outbuf, size_t outbuf_size) = 0;
    virtual transport_stream_write_result write_stream_packet(
      stream_id sid,
      const char* data,
      size_t len,
      bool fin,
      uint8_t* outbuf,
      size_t outbuf_size,
      bool more = false) = 0;
    virtual transport_open_stream_result try_open_stream(stream_type type) = 0;
    virtual int shutdown_stream_write(stream_id sid, application_error_code app_error_code) = 0;
    virtual int shutdown_stream_read(stream_id sid, application_error_code app_error_code) = 0;
    virtual int read_transport_datagram(const socket_address& src, const char* data, size_t len) = 0;
    virtual void sync_transport_path() = 0;
    virtual uint64_t transport_expiry_ns() const noexcept = 0;
    virtual int handle_transport_expiry(uint64_t now_ns) = 0;

    virtual future<> send_datagram_packet(temporary_buffer<char> packet, size_t packet_size) = 0;
    virtual bool has_queued_datagram_packets() const noexcept = 0;
    virtual future<> flush_datagram_packets() = 0;
    virtual bool can_send_connection_close() const noexcept = 0;
    virtual int64_t write_connection_close_packet(uint8_t* outbuf, size_t outbuf_size) = 0;
    virtual void on_stream_write_closed(stream_id sid) = 0;
    virtual void rearm_transport_timer() = 0;
    virtual void request_close() = 0;
    virtual void stop_transport() = 0;
    virtual void fail_transport(quic_error error, sstring detail) = 0;

    virtual void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) = 0;
    virtual void fail_open_stream(
      std::shared_ptr<promise<stream_id>> result,
      quic_error error,
      sstring detail) = 0;
    virtual void defer_blocked_open_stream(transport_command cmd) = 0;
    virtual std::optional<transport_command> pop_blocked_open_stream(stream_type type) = 0;
    virtual bool blocked_open_stream_retry_pending(stream_type type) const noexcept = 0;
    virtual void clear_blocked_open_stream_retry(stream_type type) noexcept = 0;
};

class connection_actor {
public:
    virtual ~connection_actor() = default;

    virtual bool actor_active() const noexcept = 0;
    virtual bool actor_has_pending_work() const noexcept = 0;
    virtual future<> actor_wait_for_wakeup() = 0;
    virtual bool actor_stop_requested() const noexcept = 0;
    virtual future<> actor_handle_stop_request() = 0;
    virtual bool actor_has_rx_event() const noexcept = 0;
    virtual future<> actor_handle_next_rx_event() = 0;
    virtual bool actor_has_blocked_send() const noexcept = 0;
    virtual void actor_defer_blocked_send(blocked_send_state state) = 0;
    virtual future<> actor_handle_blocked_send() = 0;
    virtual bool actor_has_transport_command() const noexcept = 0;
    virtual future<> actor_handle_next_transport_command() = 0;
    virtual future<> actor_retry_blocked_open_streams() = 0;
    virtual bool actor_tick_pending() const noexcept = 0;
    virtual void actor_clear_tick() noexcept = 0;
    virtual future<> actor_handle_timer_tick() = 0;
};

class connection_engine {
public:
    explicit connection_engine(
      session_runtime_ptr runtime,
      connection_options options = {},
      std::shared_ptr<transport_debug_stats> debug_stats = {});
    ~connection_engine();

    connection_engine(const connection_engine&) = delete;
    connection_engine& operator=(const connection_engine&) = delete;

    bool is_open() const noexcept;
    socket_address local_address() const;
    socket_address peer_address() const;
    sstring selected_alpn() const;

    future<stream> open_stream(stream_open_options options = {});
    future<stream> accept_stream();
    future<> close();

    void on_stream_data(stream_id sid, stream_type type, bool peer_initiated, temporary_buffer<char> payload, bool fin);
    void on_stream_reset(stream_id sid, stream_type type, bool peer_initiated, application_error_code app_error_code);
    void on_stream_stop_sending(
      stream_id sid,
      stream_type type,
      bool peer_initiated,
      application_error_code app_error_code,
      stream_shutdown_side shutdown_side);
    void on_stream_closed(stream_id sid);
    void on_transport_closed(std::exception_ptr ex);

    future<> wait_for_actor_wakeup(bool has_pending_work, bool closing);
    void wake_actor();

    bool tick_pending() const noexcept;
    void clear_tick() noexcept;

    void arm_timer(std::chrono::nanoseconds delay, bool closing);
    void rearm_timer_from_expiry(uint64_t expiry_ns, uint64_t now_ns, bool closing);
    void cancel_timer() noexcept;

    void defer_blocked_open_stream(transport_command cmd);
    std::optional<transport_command> pop_blocked_open_stream(stream_type type);
    void request_blocked_open_stream_retry(stream_type type);
    bool blocked_open_stream_retry_pending(stream_type type) const noexcept;
    void clear_blocked_open_stream_retry(stream_type type) noexcept;
    bool has_blocked_open_stream_retry_work() const noexcept;
    void fail_blocked_open_streams(quic_error error, std::string_view detail);

private:
    class impl;
    std::unique_ptr<impl> _impl;
};

connection_engine_ptr make_connection_engine(
  session_runtime_ptr runtime,
  connection_options options = {},
  std::shared_ptr<transport_debug_stats> debug_stats = {});

future<> flush_pending_transport_packets(connection_transport& transport);
future<> send_stream_message(connection_transport& transport, connection_actor& actor, blocked_send_state state);
future<bool> open_stream(connection_transport& transport, transport_command cmd);
future<> reset_stream(connection_transport& transport, stream_id sid, application_error_code app_error_code);
future<> stop_sending(connection_transport& transport, stream_id sid, application_error_code app_error_code);
future<> retry_blocked_open_streams(connection_transport& transport, stream_type type);
future<> handle_transport_command(connection_transport& transport, connection_actor& actor, transport_command cmd);
future<> recv_transport_datagram(connection_transport& transport, const socket_address& src, temporary_buffer<char> pkt);
future<> handle_transport_timer(connection_transport& transport);
future<> send_connection_close(connection_transport& transport);
future<> run_connection_actor(connection_transport& transport, connection_actor& actor);

session_runtime_ptr make_session_runtime(connection_options options = {});

} // namespace internal

} // namespace seastar::quic::experimental
