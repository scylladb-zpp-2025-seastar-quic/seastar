/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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

#include <seastar/quic/quic_server.hh>

#include "quic_common.hh"
#include "quic_impl.hh"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <limits>
#include <memory>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <seastar/coroutine/maybe_yield.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sleep.hh>
#include <seastar/util/log.hh>

namespace seastar::quic::experimental {

namespace {

constexpr size_t max_cid_len = 20;
constexpr size_t server_short_cid_len = 8;
constexpr size_t max_udp_payload_size = 65527;
constexpr size_t default_udp_payload_size = 1200;

static logger quic_server_log("quic_server");
using transport_command = internal::transport_command;
using quic_message = internal::quic_message;

std::string cid_key(const uint8_t* data, size_t len) {
    return std::string(reinterpret_cast<const char*>(data), len);
}

enum class quic_long_type : uint8_t {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

struct dcid_parse_result {
    bool ok = false;
    bool long_header = false;
    quic_long_type long_type = quic_long_type::initial;
    std::array<uint8_t, max_cid_len> dcid{};
    size_t dcid_len = 0;
};

dcid_parse_result parse_dcid(const uint8_t* pkt, size_t len, size_t short_dcid_len) {
    dcid_parse_result result{};
    if (len < 1) {
        return result;
    }

    const uint8_t long_header = (pkt[0] & 0x80u) != 0;
    result.long_header = long_header;
    if (long_header) {
        if (len < 1 + 4 + 1) {
            return result;
        }

        result.long_type = static_cast<quic_long_type>((pkt[0] >> 4) & 0x03u);
        size_t off = 1 + 4;
        const uint8_t cid_len = pkt[off++];
        if (cid_len > result.dcid.size() || off + cid_len > len) {
            return result;
        }

        std::memcpy(result.dcid.data(), pkt + off, cid_len);
        result.dcid_len = cid_len;
        result.ok = true;
        return result;
    }

    if (len < 1 + short_dcid_len) {
        return result;
    }
    std::memcpy(result.dcid.data(), pkt + 1, short_dcid_len);
    result.dcid_len = short_dcid_len;
    result.ok = true;
    return result;
}

struct conn_rx_event {
    socket_address src;
    temporary_buffer<char> packet;
};

struct server_connection;
void sync_current_path(server_connection& conn);

// Per-peer server-side transport state created after the first Initial packet.
struct server_connection : public enable_lw_shared_from_this<server_connection> {
    std::weak_ptr<quic_server_impl> server;
    internal::command_runtime_ptr command_runtime;
    internal::connection_state_ptr connection_state;

    ngtcp2_conn* conn = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};
    gnutls_session_t tls = nullptr;

    socket_address peer{};
    sockaddr_storage local_ss{};
    socklen_t local_ss_len = 0;
    sockaddr_storage peer_ss{};
    socklen_t peer_ss_len = 0;

    queue<conn_rx_event> rx_queue{1024};
    bool queues_aborted = false;
    bool unregistered = false;
    bool stop_requested = false;
    std::optional<quic_error_code> stop_error;
    sstring stop_error_detail;

    bool closing = false;
    bool handshake_done = false;
    bool accepted_to_listener = false;
    size_t tx_payload_limit = default_udp_payload_size;
    temporary_buffer<char> tx_packet_scratch;
    std::optional<transport_command> blocked_send_command;
    bool blocked_send_retry_requested = false;
    std::unordered_set<std::string> mapped_dcids;
    internal::connection_transport transport;

    server_connection()
        : transport(internal::make_connection_transport(*this)) {
    }

    ~server_connection() {
        fail_blocked_open_streams(quic_error_code::closed, "server connection destroyed");
        discard_blocked_send();
        abort_event_queues("server connection destroyed");
        if (command_runtime) {
            command_runtime->set_command_notifier({});
        }
        wake_actor();
        if (conn) {
            ngtcp2_conn_del(conn);
            conn = nullptr;
        }
        if (tls) {
            gnutls_deinit(tls);
            tls = nullptr;
        }
    }

    void fill_path(ngtcp2_path& path) {
        init_ngtcp2_addr(&path.local, reinterpret_cast<sockaddr*>(&local_ss), local_ss_len);
        init_ngtcp2_addr(&path.remote, reinterpret_cast<sockaddr*>(&peer_ss), peer_ss_len);
    }

    std::shared_ptr<quic_server_impl> lock_server() const {
        return server.lock();
    }

    bool transport_active() const noexcept {
        return active();
    }

    bool has_transport_connection() const noexcept {
        return conn != nullptr;
    }

    bool can_retry_blocked_open_streams() const noexcept {
        return active() && !stop_requested;
    }

    size_t tx_payload_limit_bytes() const noexcept {
        return tx_payload_limit;
    }

    bool has_blocked_send() const noexcept {
        return blocked_send_command.has_value();
    }

    bool blocked_send_retry_pending() const noexcept {
        return has_blocked_send() && blocked_send_retry_requested;
    }

    bool has_pending_actor_work() const noexcept {
        return stop_requested
               || (command_runtime && command_runtime->transport_terminal())
               || !rx_queue.empty()
               || blocked_send_retry_pending()
               || (!has_blocked_send() && command_runtime && command_runtime->has_pending_commands())
               || connection_state->tick_pending()
               || connection_state->has_blocked_open_stream_retry_work();
    }

    future<> wait_for_actor_wakeup() {
        return connection_state->wait_for_actor_wakeup(has_pending_actor_work(), closing);
    }

    void wake_actor() {
        connection_state->wake_actor();
    }

    int64_t write_pending_packet(uint8_t* outbuf, size_t outbuf_size) {
        ngtcp2_path path{};
        fill_path(path);
        ngtcp2_pkt_info pkt_info{};
        return ngtcp2_conn_write_pkt(conn, &path, &pkt_info, outbuf, outbuf_size, quic_now_ns());
    }

    internal::transport_stream_write_result write_stream_packet(
      stream_id sid,
      const char* data,
      size_t len,
      bool fin,
      uint8_t* outbuf,
      size_t outbuf_size) {
        ngtcp2_path path{};
        fill_path(path);
        ngtcp2_pkt_info pkt_info{};
        ngtcp2_vec vec{};
        ngtcp2_ssize consumed = 0;
        if (data && len) {
            vec.base = reinterpret_cast<uint8_t*>(const_cast<char*>(data));
            vec.len = len;
        }
        auto flags = (!len && fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
        auto nwrite = ngtcp2_conn_writev_stream(
          conn,
          &path,
          &pkt_info,
          outbuf,
          outbuf_size,
          &consumed,
          flags,
          sid,
          (data && len) ? &vec : nullptr,
          (data && len) ? 1 : 0,
          quic_now_ns());
        return internal::transport_stream_write_result{
          .nwrite = nwrite,
          .consumed = consumed > 0 ? static_cast<size_t>(consumed) : 0,
        };
    }

    void complete_send_bytes(size_t len) {
        if (command_runtime) {
            command_runtime->complete_send_bytes(len);
        }
    }

    internal::transport_open_stream_result try_open_stream(stream_type type) {
        int64_t sid = invalid_stream_id;
        auto rv = type == stream_type::bidirectional
                    ? ngtcp2_conn_open_bidi_stream(conn, &sid, nullptr)
                    : ngtcp2_conn_open_uni_stream(conn, &sid, nullptr);
        return internal::transport_open_stream_result{
          .rv = rv,
          .sid = sid,
        };
    }

    int shutdown_stream_write(stream_id sid, application_error_code app_error_code) {
        return ngtcp2_conn_shutdown_stream_write(conn, 0, sid, app_error_code);
    }

    int consume_stream_data(stream_id sid, size_t len) {
        if (!conn || !len) {
            return 0;
        }
        auto rv = ngtcp2_conn_extend_max_stream_offset(conn, sid, static_cast<uint64_t>(len));
        if (rv < 0) {
            return rv;
        }
        ngtcp2_conn_extend_max_offset(conn, static_cast<uint64_t>(len));
        return 0;
    }

    int shutdown_stream_read(stream_id sid, application_error_code app_error_code) {
        return ngtcp2_conn_shutdown_stream_read(conn, 0, sid, app_error_code);
    }

    int read_transport_datagram(const socket_address& src, const char* data, size_t len) {
        sockaddr_storage peer_addr_ss{};
        socklen_t peer_addr_ss_len = 0;
        to_sockaddr_storage(src, peer_addr_ss, peer_addr_ss_len);

        ngtcp2_path path{};
        init_ngtcp2_addr(&path.local, reinterpret_cast<sockaddr*>(&local_ss), local_ss_len);
        init_ngtcp2_addr(&path.remote, reinterpret_cast<sockaddr*>(&peer_addr_ss), peer_addr_ss_len);
        ngtcp2_pkt_info pkt_info{};
        return ngtcp2_conn_read_pkt(
          conn,
          &path,
          &pkt_info,
          reinterpret_cast<const uint8_t*>(data),
          len,
          quic_now_ns());
    }

    void sync_transport_path() {
        sync_current_path(*this);
    }

    uint64_t transport_expiry_ns() const noexcept {
        return ngtcp2_conn_get_expiry(conn);
    }

    int handle_transport_expiry(uint64_t now_local) {
        return ngtcp2_conn_handle_expiry(conn, now_local);
    }

    temporary_buffer<char>& tx_packet_buffer() {
        return tx_packet_scratch;
    }

    future<> send_datagram_packet(temporary_buffer<char> packet);

    bool can_send_connection_close() const noexcept;

    int64_t write_connection_close_packet(uint8_t* outbuf, size_t outbuf_size) {
        ngtcp2_path path{};
        fill_path(path);
        ngtcp2_pkt_info pkt_info{};
        ngtcp2_ccerr ccerr{};
        ngtcp2_ccerr_default(&ccerr);
        ngtcp2_ccerr_set_application_error(&ccerr, 0, nullptr, 0);
        return ngtcp2_conn_write_connection_close(
          conn,
          &path,
          &pkt_info,
          outbuf,
          outbuf_size,
          &ccerr,
          quic_now_ns());
    }

    void on_stream_write_closed(stream_id sid) {
        if (!connection_state || !conn) {
            return;
        }
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(conn, sid);
        connection_state->on_stream_stop_sending(sid, type, peer_initiated, 0, internal::stream_shutdown_side::write);
    }

    void rearm_transport_timer() {
        if (!connection_state) {
            return;
        }
        if (!conn) {
            connection_state->cancel_timer();
            return;
        }
        connection_state->rearm_timer_from_expiry(ngtcp2_conn_get_expiry(conn), quic_now_ns(), closing);
    }

    void request_close() {
        request_stop();
    }

    void cancel_transport_timer() {
        if (connection_state) {
            connection_state->cancel_timer();
        }
    }

    void abort_event_queues(const char* why) {
        if (queues_aborted) {
            return;
        }
        queues_aborted = true;
        auto ex = std::make_exception_ptr(std::runtime_error(why));
        rx_queue.abort(ex);
    }

    void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) {
        if (command_runtime) {
            command_runtime->complete_open_stream(std::move(result), sid);
        }
    }

    void fail_open_stream(
      std::shared_ptr<promise<stream_id>> result,
      quic_error_code error,
      sstring detail) {
        if (command_runtime) {
            command_runtime->fail_open_stream(std::move(result), error, std::move(detail));
        }
    }

    bool blocked_open_stream_retry_pending(stream_type type) const noexcept {
        return connection_state->blocked_open_stream_retry_pending(type);
    }

    void defer_blocked_open_stream(transport_command cmd) {
        connection_state->defer_blocked_open_stream(std::move(cmd));
    }

    std::optional<transport_command> pop_blocked_open_stream(stream_type type) {
        return connection_state->pop_blocked_open_stream(type);
    }

    void request_blocked_open_stream_retry(stream_type type) {
        connection_state->request_blocked_open_stream_retry(type);
    }

    void defer_blocked_send(transport_command cmd) {
        blocked_send_command = std::move(cmd);
        blocked_send_retry_requested = false;
    }

    std::optional<transport_command> take_blocked_send() {
        if (!blocked_send_command) {
            return std::nullopt;
        }
        auto cmd = std::move(*blocked_send_command);
        blocked_send_command.reset();
        blocked_send_retry_requested = false;
        return cmd;
    }

    void request_blocked_send_retry() {
        if (!blocked_send_command) {
            return;
        }
        blocked_send_retry_requested = true;
        wake_actor();
    }

    void clear_blocked_send_retry() noexcept {
        blocked_send_retry_requested = false;
    }

    void discard_blocked_send() {
        if (!blocked_send_command) {
            return;
        }
        complete_send_bytes(blocked_send_command->msg.payload.size());
        blocked_send_command.reset();
        blocked_send_retry_requested = false;
    }

    void clear_blocked_open_stream_retry(stream_type type) noexcept {
        connection_state->clear_blocked_open_stream_retry(type);
    }

    void fail_blocked_open_streams(quic_error_code error, std::string_view detail) {
        if (!connection_state) {
            return;
        }
        connection_state->fail_blocked_open_streams(error, detail);
    }

    void request_stop() {
        if (closing || stop_requested) {
            return;
        }
        stop_requested = true;
        fail_blocked_open_streams(quic_error_code::closed, "server connection stopping");
        cancel_transport_timer();
        wake_actor();
    }

    bool active() const noexcept;
    bool actor_active() const noexcept {
        return active();
    }
    bool actor_has_pending_work() const noexcept {
        return has_pending_actor_work();
    }
    future<> actor_wait_for_wakeup() {
        return wait_for_actor_wakeup();
    }
    bool actor_stop_requested() const noexcept {
        return stop_requested;
    }
    future<> actor_handle_stop_request();
    bool actor_transport_terminal() const noexcept {
        return command_runtime && command_runtime->transport_terminal();
    }
    future<> actor_handle_transport_terminal() {
        if (!command_runtime) {
            co_return;
        }
        if (command_runtime->transport_failed()) {
            fail(command_runtime->transport_error(), command_runtime->transport_error_detail());
        } else {
            stop_transport();
        }
        co_return;
    }
    bool actor_has_rx_event() const noexcept {
        return !rx_queue.empty();
    }
    future<> actor_handle_next_rx_event();
    bool actor_has_transport_command() const noexcept {
        return blocked_send_retry_pending()
               || (!has_blocked_send() && command_runtime && command_runtime->has_pending_commands());
    }
    future<> actor_handle_next_transport_command() {
        std::optional<transport_command> cmd;
        // Retry a blocked send before taking a new command so the connection keeps
        // its original send ordering.
        if (blocked_send_retry_pending()) {
            clear_blocked_send_retry();
            cmd = take_blocked_send();
        } else if (!has_blocked_send() && command_runtime) {
            cmd = command_runtime->poll_command();
        }
        if (!cmd) {
            co_return;
        }
        auto blocked = co_await internal::handle_transport_command(transport, std::move(*cmd));
        if (blocked) {
            defer_blocked_send(std::move(*blocked));
        }
    }
    future<> actor_retry_blocked_open_streams() {
        co_await internal::retry_blocked_open_streams(transport, stream_type::bidirectional);
        co_await internal::retry_blocked_open_streams(transport, stream_type::unidirectional);
    }
    bool actor_tick_pending() const noexcept {
        return connection_state->tick_pending();
    }
    void actor_clear_tick() noexcept {
        connection_state->clear_tick();
    }
    future<> actor_handle_timer_tick();
    void stop_transport();
    void fail(quic_error_code error, const sstring& detail);
    void fail_transport(quic_error_code error, sstring detail);
};

using conn_ptr = lw_shared_ptr<server_connection>;

void sync_current_path(server_connection& conn) {
    if (!conn.conn) {
        return;
    }

    const auto tx_payload_limit = effective_tx_payload_limit(conn.conn, default_udp_payload_size, max_udp_payload_size);
    const auto* path = ngtcp2_conn_get_path(conn.conn);
    if (!path) {
        conn.tx_payload_limit = tx_payload_limit;
        return;
    }

    auto local = to_socket_address(path->local);
    auto remote = to_socket_address(path->remote);
    if (!local || !remote) {
        return;
    }

    auto old_local = to_socket_address(ngtcp2_addr{
      reinterpret_cast<ngtcp2_sockaddr*>(&conn.local_ss),
      static_cast<ngtcp2_socklen>(conn.local_ss_len),
    });

    if ((!old_local || *local == *old_local) && *remote == conn.peer && tx_payload_limit == conn.tx_payload_limit) {
        return;
    }

    quic_server_log.info(
      "server active path updated: old_local={} old_remote={} new_local={} new_remote={} tx_payload_limit={} old_tx_payload_limit={}",
      old_local.value_or(socket_address{}),
      conn.peer,
      *local,
      *remote,
      tx_payload_limit,
      conn.tx_payload_limit);

    conn.peer = *remote;
    conn.tx_payload_limit = tx_payload_limit;
    to_sockaddr_storage(*local, conn.local_ss, conn.local_ss_len);
    to_sockaddr_storage(conn.peer, conn.peer_ss, conn.peer_ss_len);
}

} // namespace

// Owns the listener socket and tracks the set of active server-side connections.
class quic_server_impl : public std::enable_shared_from_this<quic_server_impl> {
public:
    quic_server_impl() = default;
    virtual ~quic_server_impl() {
        request_stop_detached();
        cleanup_resources();
    }

    future<> start(quic_server_config cfg) {
        if (_started) {
            throw_quic_error(quic_error_code::invalid_state, "server already started");
        }
        ensure_gnutls_global();
        validate_ip_socket_address(cfg.listen_address, "listen_address");
        quic_server_log.info(
          "server start: listen={} crt_file='{}' key_file='{}' alpn_count={}",
          cfg.listen_address,
          cfg.crt_file,
          cfg.key_file,
          cfg.alpns.size());

        _cfg = std::move(cfg);
        int rv = gnutls_certificate_allocate_credentials(&_cred);
        if (rv < 0) {
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }

        rv = gnutls_certificate_set_x509_key_file(
          _cred, _cfg.crt_file.c_str(), _cfg.key_file.c_str(), GNUTLS_X509_FMT_PEM);
        if (rv < 0) {
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }

        _channel = engine().net().make_bound_datagram_channel(_cfg.listen_address);
        _channel_ready = true;
        _listen_address = _channel.local_address();
        _started = true;
        _stopping = false;
        quic_server_log.info("server listening on {}", _listen_address);

        auto self = shared_from_this();
        (void)with_gate(_task_gate, [self] { return self->receive_loop(); })
          .handle_exception([self](std::exception_ptr) {
              if (!self->_stopping) {
                  quic_server_log.error("server receive loop failed");
                  self->_stopping = true;
                  self->_accept_cv.broadcast();
              }
          })
          .or_terminate();
        co_return;
    }

    future<internal::connection_state_ptr> accept() {
        if (!_started) {
            throw_quic_error(quic_error_code::invalid_state, "server is not started");
        }
        quic_server_log.debug("server accept wait: pending_accepted={} active_conns={}", _accepted.size(), _conns.size());

        while (_accepted.empty()) {
            if (_stopping) {
                throw_quic_error(quic_error_code::closed, "server stopped");
            }
            co_await _accept_cv.wait();
        }

        auto connection_state = std::move(_accepted.front());
        _accepted.pop_front();
        quic_server_log.info("server accept ready: pending_accepted={} active_conns={}", _accepted.size(), _conns.size());
        co_return connection_state;
    }

    future<> stop() {
        if (!_started) {
            quic_server_log.debug("server stop ignored: not started");
            co_return;
        }

        quic_server_log.info(
          "server stop start: listen={} active_conns={} pending_accepted={} mapped_dcids={}",
          _listen_address,
          _conns.size(),
          _accepted.size(),
          _by_dcid.size());
        request_stop();

        co_await _task_gate.close();

        cleanup_resources();
        _started = false;
        _stopping = false;
        quic_server_log.info("server stop complete");
    }

    bool stopping() const noexcept {
        return _stopping;
    }

    void request_stop() noexcept {
        request_stop_impl(false);
    }

    void request_stop_detached() noexcept {
        request_stop_impl(true);
    }

private:
    void request_stop_impl(bool detached) noexcept {
        if (!_started || _stopping) {
            return;
        }

        if (detached) {
            quic_server_log.warn("quic_server destroyed or orphaned without awaiting stop(); shutting down detached");
        }
        _stopping = true;
        _accept_cv.broadcast();

        auto conns_copy = _conns;
        for (auto& conn : conns_copy) {
            conn->stop_transport();
        }

        if (_channel_ready && !_channel.is_closed()) {
            try {
                _channel.shutdown_input();
            } catch (...) {
            }
        }
    }

public:
    net::datagram_channel& channel() {
        return _channel;
    }

    void map_dcid(const conn_ptr& conn, const uint8_t* cid, size_t len) {
        auto key = cid_key(cid, len);
        _by_dcid[key] = conn;
        conn->mapped_dcids.insert(std::move(key));
        quic_server_log.debug("server map DCID: len={} total_mapped={} conn_mapped={}", len, _by_dcid.size(), conn->mapped_dcids.size());
    }

    void unmap_dcid(const conn_ptr& conn, const uint8_t* cid, size_t len) {
        auto key = cid_key(cid, len);
        auto it = _by_dcid.find(key);
        if (it != _by_dcid.end() && it->second == conn) {
            _by_dcid.erase(it);
        }
        conn->mapped_dcids.erase(key);
        quic_server_log.debug("server unmap DCID: len={} total_mapped={} conn_mapped={}", len, _by_dcid.size(), conn->mapped_dcids.size());
    }

    void unregister_connection(const conn_ptr& conn) {
        if (!conn || conn->unregistered) {
            return;
        }
        conn->unregistered = true;
        quic_server_log.info("server unregister connection: peer={} mapped_dcids={} active_conns_before={}", conn->peer, conn->mapped_dcids.size(), _conns.size());
        for (const auto& key : conn->mapped_dcids) {
            auto it = _by_dcid.find(key);
            if (it != _by_dcid.end() && it->second == conn) {
                _by_dcid.erase(it);
            }
        }
        conn->mapped_dcids.clear();

        _conns.erase(std::remove(_conns.begin(), _conns.end(), conn), _conns.end());
        quic_server_log.info("server connection unregistered: active_conns={} mapped_dcids={}", _conns.size(), _by_dcid.size());
    }

    void enqueue_accepted_session(const internal::connection_state_ptr& connection_state) {
        _accepted.push_back(connection_state);
        quic_server_log.debug("server queued accepted session: pending_accepted={}", _accepted.size());
        _accept_cv.signal();
    }

    gnutls_certificate_credentials_t credentials() const {
        return _cred;
    }

    const quic_server_config& config() const {
        return _cfg;
    }

    const socket_address& listen_address() const {
        return _listen_address;
    }

private:
    void cleanup_resources() noexcept {
        if (_channel_ready && !_channel.is_closed()) {
            try {
                _channel.shutdown_output();
            } catch (...) {
            }
            try {
                _channel.close();
            } catch (...) {
            }
        }

        _conns.clear();
        _by_dcid.clear();
        _accepted.clear();
        if (_cred) {
            gnutls_certificate_free_credentials(_cred);
            _cred = nullptr;
        }
        _channel_ready = false;
    }

    friend struct server_connection;

    static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref) {
        return static_cast<ngtcp2_conn*>(ref->user_data);
    }

    static void rand_cb(uint8_t* dest, size_t len, const ngtcp2_rand_ctx*) {
        if (!rand_bytes_or_log(quic_server_log, "server", dest, len, "ngtcp2 rand callback")) {
            std::terminate();
        }
    }

    static int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void*) {
        cid->datalen = cidlen;
        if (!rand_bytes_or_log(quic_server_log, "server", cid->data, cidlen, "connection id generation")) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (!rand_bytes_or_log(quic_server_log, "server", token, NGTCP2_STATELESS_RESET_TOKENLEN, "stateless reset token generation")) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    static int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t* data, void*) {
        if (!rand_bytes_or_log(quic_server_log, "server", data, 8, "path challenge generation")) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    static sstring selected_alpn_or_empty(gnutls_session_t tls) {
        gnutls_datum_t selected{};
        if (gnutls_alpn_get_selected_protocol(tls, &selected) != 0 || !selected.data) {
            return {};
        }
        return {reinterpret_cast<const char*>(selected.data), selected.size};
    }

    static int handshake_completed_cb(ngtcp2_conn*, void* user_data) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->command_runtime) {
            return 0;
        }
        auto server = conn->lock_server();
        conn->handshake_done = true;
        sync_current_path(*conn);
        conn->command_runtime->mark_transport_ready(
          to_socket_address(ngtcp2_conn_get_path(conn->conn)->local).value_or(
            server ? server->listen_address() : socket_address{}),
          conn->peer,
          selected_alpn_or_empty(conn->tls));
        if (!conn->accepted_to_listener && server && conn->connection_state) {
            conn->accepted_to_listener = true;
            server->enqueue_accepted_session(conn->connection_state);
        }
        quic_server_log.info("server handshake completed: peer={} alpn='{}'", conn->peer, conn->command_runtime->selected_alpn());
        conn->wake_actor();
        conn->rearm_transport_timer();
        return 0;
    }

    static int begin_path_validation_cb(ngtcp2_conn*, uint32_t, const ngtcp2_path* path, const ngtcp2_path*, void* user_data) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !path) {
            return 0;
        }

        auto remote = to_socket_address(path->remote);
        if (remote) {
            quic_server_log.info("server begin path validation: peer={} candidate_remote={}", conn->peer, *remote);
        }
        return 0;
    }

    static int path_validation_cb(
      ngtcp2_conn*,
      uint32_t,
      const ngtcp2_path* path,
      const ngtcp2_path* fallback_path,
      ngtcp2_path_validation_result res,
      void* user_data) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn) {
            return 0;
        }

        auto candidate = path ? to_socket_address(path->remote) : std::nullopt;
        auto fallback = fallback_path ? to_socket_address(fallback_path->remote) : std::nullopt;
        quic_server_log.info("server path validation complete: peer={} result={} candidate_remote={} fallback_remote={}",
          conn->peer,
          res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "success" : "failure",
          candidate.value_or(socket_address{}),
          fallback.value_or(socket_address{}));

        sync_current_path(*conn);
        return 0;
    }

    static int dcid_status_cb(ngtcp2_conn*, ngtcp2_connection_id_status_type type, uint64_t, const ngtcp2_cid* cid, const uint8_t*, void* user_data) {
        auto* conn = static_cast<server_connection*>(user_data);
        auto server = conn ? conn->lock_server() : nullptr;
        if (!conn || !server || !cid) {
            return 0;
        }
        auto self = conn->shared_from_this();
        if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE) {
            quic_server_log.debug("server dcid activate: peer={} len={}", conn->peer, cid->datalen);
            server->map_dcid(self, cid->data, cid->datalen);
        } else if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE) {
            quic_server_log.debug("server dcid deactivate: peer={} len={}", conn->peer, cid->datalen);
            server->unmap_dcid(self, cid->data, cid->datalen);
        }
        return 0;
    }

    static int recv_stream_data_cb(ngtcp2_conn* ngconn, uint32_t flags, int64_t sid, uint64_t, const uint8_t* data, size_t datalen, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->connection_state || !conn->connection_state->is_open()) {
            quic_server_log.trace("server drop recv_stream_data: sid={} bytes={} conn_valid={} engine_open={}",
              sid, datalen, conn != nullptr, conn && conn->connection_state && conn->connection_state->is_open());
            return 0;
        }
        quic_server_log.trace("server recv_stream_data: peer={} sid={} bytes={}", conn->peer, sid, datalen);
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(ngconn, sid);
        temporary_buffer<char> tb(datalen);
        if (datalen) {
            std::memcpy(tb.get_write(), data, datalen);
        }
        conn->connection_state->on_stream_data(sid, type, peer_initiated, std::move(tb), (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
        return 0;
    }

    static int stream_reset_cb(ngtcp2_conn* ngconn, int64_t sid, uint64_t, uint64_t app_error_code, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->connection_state) {
            return 0;
        }
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(ngconn, sid);
        conn->connection_state->on_stream_reset(sid, type, peer_initiated, app_error_code);
        return 0;
    }

    static int stream_stop_sending_cb(ngtcp2_conn* ngconn, int64_t sid, uint64_t app_error_code, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->connection_state) {
            return 0;
        }
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(ngconn, sid);
        conn->connection_state->on_stream_stop_sending(sid, type, peer_initiated, app_error_code, internal::stream_shutdown_side::write);
        return 0;
    }

    static int stream_close_cb(ngtcp2_conn*, uint32_t, int64_t sid, uint64_t, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->connection_state) {
            return 0;
        }

        conn->connection_state->on_stream_closed(sid);
        return 0;
    }

    static int extend_max_local_streams_bidi_cb(ngtcp2_conn*, uint64_t max_streams, void* user_data) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn) {
            return 0;
        }
        quic_server_log.debug("server local bidi stream capacity extended: peer={} max_streams={}", conn->peer, max_streams);
        conn->request_blocked_open_stream_retry(stream_type::bidirectional);
        return 0;
    }

    static int extend_max_local_streams_uni_cb(ngtcp2_conn*, uint64_t max_streams, void* user_data) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn) {
            return 0;
        }
        quic_server_log.debug("server local uni stream capacity extended: peer={} max_streams={}", conn->peer, max_streams);
        conn->request_blocked_open_stream_retry(stream_type::unidirectional);
        return 0;
    }

    gnutls_session_t make_tls_session(server_connection& conn) const {
        gnutls_session_t tls = nullptr;
        int rv = gnutls_init(&tls, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA);
        if (rv < 0) {
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }
        rv = gnutls_credentials_set(tls, GNUTLS_CRD_CERTIFICATE, _cred);
        if (rv < 0) {
            gnutls_deinit(tls);
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }
        rv = gnutls_priority_set_direct(tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr);
        if (rv < 0) {
            gnutls_deinit(tls);
            throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
        }

        std::vector<gnutls_datum_t> alpns;
        alpns.reserve(_cfg.alpns.size());
        for (const auto& alpn : _cfg.alpns) {
            alpns.push_back(gnutls_datum_t{
              reinterpret_cast<unsigned char*>(const_cast<char*>(alpn.data())),
              static_cast<unsigned int>(alpn.size()),
            });
        }
        if (!alpns.empty()) {
            rv = gnutls_alpn_set_protocols(tls, alpns.data(), alpns.size(), 0);
            if (rv < 0) {
                gnutls_deinit(tls);
                throw_quic_error(classify_gnutls_error(rv), gnutls_error_message(rv));
            }
        }

        rv = ngtcp2_crypto_gnutls_configure_server_session(tls);
        if (rv != 0) {
            gnutls_deinit(tls);
            throw_quic_error(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        }

        conn.conn_ref.get_conn = get_conn;
        conn.conn_ref.user_data = nullptr;
        gnutls_session_set_ptr(tls, &conn.conn_ref);
        return tls;
    }

    conn_ptr init_connection(const socket_address& peer, const uint8_t* pkt, size_t pkt_len) {
        quic_server_log.info("server init_connection: peer={} first_packet_bytes={}", peer, pkt_len);
        auto conn = make_lw_shared<server_connection>();
        conn->server = shared_from_this();
        conn->command_runtime = internal::make_command_runtime(_cfg.session_options);
        conn->connection_state = internal::make_connection_state(conn->command_runtime, _cfg.session_options);
        conn->rx_queue.set_max_size(recommended_rx_queue_capacity(_cfg.session_options));
        conn->command_runtime->set_command_notifier([raw = conn.get()] {
            raw->wake_actor();
        });
        conn->peer = peer;
        to_sockaddr_storage(_listen_address, conn->local_ss, conn->local_ss_len);
        to_sockaddr_storage(peer, conn->peer_ss, conn->peer_ss_len);
        conn->tls = make_tls_session(*conn);

        ngtcp2_version_cid vc{};
        int rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, pkt_len, NGTCP2_MAX_CIDLEN);
        if (rv < 0) {
            throw_quic_error(quic_error_code::protocol, "failed to decode Initial CID");
        }

        ngtcp2_cid dcid{};
        dcid.datalen = vc.scidlen;
        std::memcpy(dcid.data, vc.scid, vc.scidlen);

        ngtcp2_cid odcid{};
        odcid.datalen = vc.dcidlen;
        std::memcpy(odcid.data, vc.dcid, vc.dcidlen);

        ngtcp2_cid scid{};
        scid.datalen = server_short_cid_len;
        rand_bytes_or_throw(scid.data, scid.datalen, "connection id generation");

        ngtcp2_callbacks callbacks{};
        callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
        callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
        callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
        callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
        callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
        callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
        callbacks.update_key = ngtcp2_crypto_update_key_cb;
        callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
        callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
        callbacks.rand = rand_cb;
        callbacks.get_new_connection_id = get_new_connection_id_cb;
        callbacks.get_path_challenge_data = get_path_challenge_data_cb;
        callbacks.path_validation = path_validation_cb;
        callbacks.begin_path_validation = begin_path_validation_cb;
        callbacks.handshake_completed = handshake_completed_cb;
        callbacks.dcid_status = dcid_status_cb;
        callbacks.recv_stream_data = recv_stream_data_cb;
        callbacks.stream_close = stream_close_cb;
        callbacks.stream_reset = stream_reset_cb;
        callbacks.stream_stop_sending = stream_stop_sending_cb;
        callbacks.extend_max_local_streams_bidi = extend_max_local_streams_bidi_cb;
        callbacks.extend_max_local_streams_uni = extend_max_local_streams_uni_cb;

        ngtcp2_settings settings{};
        ngtcp2_settings_default(&settings);
        settings.initial_ts = quic_now_ns();
        if (_cfg.session_options.transport.initial_rtt_ns
            && *_cfg.session_options.transport.initial_rtt_ns > 0) {
            settings.initial_rtt = *_cfg.session_options.transport.initial_rtt_ns;
        }
        if (_cfg.session_options.transport.max_tx_udp_payload_size) {
            settings.max_tx_udp_payload_size = *_cfg.session_options.transport.max_tx_udp_payload_size;
        }
        if (_cfg.session_options.transport.max_window) {
            settings.max_window = *_cfg.session_options.transport.max_window;
        }
        if (_cfg.session_options.transport.max_stream_window) {
            settings.max_stream_window = *_cfg.session_options.transport.max_stream_window;
        }
        if (_cfg.session_options.transport.ack_thresh) {
            settings.ack_thresh = *_cfg.session_options.transport.ack_thresh;
        }
        if (auto algo = effective_congestion_control(_cfg.session_options.transport)) {
            settings.cc_algo = to_ngtcp2_cc_algo(*algo);
        }
        settings.no_tx_udp_payload_size_shaping =
          _cfg.session_options.transport.disable_tx_udp_payload_size_shaping ? 1 : 0;
        settings.no_pmtud = _cfg.session_options.transport.disable_pmtud ? 1 : 0;

        ngtcp2_transport_params params{};
        ngtcp2_transport_params_default(&params);
        params.original_dcid_present = 1;
        params.original_dcid = odcid;
        params.initial_max_stream_data_bidi_local =
          _cfg.session_options.transport.initial_max_stream_data_bidi_local;
        params.initial_max_stream_data_bidi_remote =
          _cfg.session_options.transport.initial_max_stream_data_bidi_remote;
        params.initial_max_stream_data_uni =
          _cfg.session_options.transport.initial_max_stream_data_uni;
        params.initial_max_data = _cfg.session_options.transport.initial_max_data;
        params.initial_max_streams_bidi = _cfg.session_options.transport.initial_max_streams_bidi;
        params.initial_max_streams_uni = _cfg.session_options.transport.initial_max_streams_uni;
        params.max_idle_timeout = _cfg.session_options.transport.max_idle_timeout_ns;
        if (_cfg.session_options.transport.max_udp_payload_size) {
            params.max_udp_payload_size = *_cfg.session_options.transport.max_udp_payload_size;
        }
        params.disable_active_migration = 1;

        ngtcp2_path path{};
        conn->fill_path(path);
        rv = ngtcp2_conn_server_new(
          &conn->conn,
          &dcid,
          &scid,
          &path,
          NGTCP2_PROTO_VER_V1,
          &callbacks,
          &settings,
          &params,
          ngtcp2_mem_for_thread(),
          conn.get());
        if (rv != 0) {
            throw_quic_error(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        }

        ngtcp2_conn_set_tls_native_handle(conn->conn, conn->tls);
        conn->conn_ref.user_data = conn->conn;

        conn->tx_payload_limit = effective_tx_payload_limit(conn->conn, default_udp_payload_size, max_udp_payload_size);

        map_dcid(conn, odcid.data, odcid.datalen);
        map_dcid(conn, scid.data, scid.datalen);
        _conns.push_back(conn);
        quic_server_log.info(
          "server connection initialized: peer={} tx_payload_limit={} active_conns={} odcid_len={} scid_len={}",
          conn->peer,
          conn->tx_payload_limit,
          _conns.size(),
          odcid.datalen,
          scid.datalen);

        auto self = shared_from_this();
        (void)with_gate(_task_gate, [self, conn] { return conn_actor_loop(conn); })
          .handle_exception([self, conn](std::exception_ptr) {
              conn->closing = true;
              conn->abort_event_queues("server actor loop failed");
              if (conn->command_runtime && conn->command_runtime->is_open()) {
                  conn->command_runtime->mark_error(quic_error_code::io, "server actor loop failed");
              }
              if (auto server = conn->lock_server()) {
                  server->unregister_connection(conn);
              }
          })
          .or_terminate();
        return conn;
    }

    static future<> flush_pending_packets_actor(conn_ptr conn) {
        co_await internal::flush_pending_transport_packets(conn->transport);
    }

    static future<> conn_actor_loop(conn_ptr conn) {
        constexpr size_t actor_batch_limit = 256;

        while (conn->actor_active()) {
            if (!conn->actor_has_pending_work()) {
                co_await conn->actor_wait_for_wakeup();
                if (!conn->actor_active()) {
                    co_return;
                }
            }

            if (conn->actor_stop_requested()) {
                co_await conn->actor_handle_stop_request();
                co_return;
            }

            if (conn->actor_transport_terminal()) {
                co_await conn->actor_handle_transport_terminal();
                continue;
            }

            size_t rx_processed = 0;
            while (conn->actor_active()
                   && !conn->actor_stop_requested()
                   && conn->actor_has_rx_event()
                   && rx_processed < actor_batch_limit) {
                co_await conn->actor_handle_next_rx_event();
                ++rx_processed;
            }

            size_t commands_processed = 0;
            while (conn->actor_active()
                   && !conn->actor_stop_requested()
                   && conn->actor_has_transport_command()
                   && commands_processed < actor_batch_limit) {
                co_await conn->actor_handle_next_transport_command();
                ++commands_processed;
            }

            if (conn->actor_active() && !conn->actor_stop_requested()) {
                co_await conn->actor_retry_blocked_open_streams();
            }

            if (conn->actor_active() && !conn->actor_stop_requested() && conn->actor_tick_pending()) {
                conn->actor_clear_tick();
                co_await conn->actor_handle_timer_tick();
            }

            if (conn->actor_active()
                && !conn->actor_stop_requested()
                && conn->actor_has_pending_work()
                && (rx_processed == actor_batch_limit || commands_processed == actor_batch_limit)) {
                // Yield between batches so one busy peer does not starve other work.
                co_await seastar::coroutine::maybe_yield();
            }
        }
    }

    void handle_datagram(net::datagram d) {
        auto src = d.get_src();
        auto pkt = linearize_packet(d.get_buffers());
        const auto* data = reinterpret_cast<const uint8_t*>(pkt.get());
        const size_t len = pkt.size();
        quic_server_log.trace("server received datagram: src={} bytes={}", src, len);

        auto parsed = parse_dcid(data, len, server_short_cid_len);
        if (!parsed.ok) {
            quic_server_log.debug("server drop datagram: failed to parse DCID src={} bytes={}", src, len);
            return;
        }

        conn_ptr conn;
        auto it = _by_dcid.find(cid_key(parsed.dcid.data(), parsed.dcid_len));
        if (it != _by_dcid.end()) {
            conn = it->second;
        }

        if (!conn) {
            if (!parsed.long_header || parsed.long_type != quic_long_type::initial) {
                quic_server_log.debug("server drop datagram: unknown DCID and not Initial src={} long_header={} long_type={}",
                  src, parsed.long_header, static_cast<unsigned>(parsed.long_type));
                return;
            }
            try {
                conn = init_connection(src, data, len);
            } catch (...) {
                quic_server_log.warn("server failed to initialize connection from Initial packet: src={} bytes={}", src, len);
                return;
            }
        }

        if (!conn || conn->closing) {
            quic_server_log.debug("server drop datagram: conn missing/closing src={}", src);
            return;
        }

        try {
            if (!conn->rx_queue.push(conn_rx_event{src, std::move(pkt)})) {
                quic_server_log.warn("server rx queue full: peer={} queued={} max={}", conn->peer, conn->rx_queue.size(), conn->rx_queue.max_size());
                conn->fail(quic_error_code::io, "server rx queue is full");
                return;
            }
            conn->wake_actor();
        } catch (...) {
            if (!conn->active()) {
                return;
            }
            conn->fail(quic_error_code::io, "server rx queue push failed");
        }
    }

    future<> receive_loop() {
        while (!_stopping) {
            try {
                auto d = co_await _channel.receive();
                handle_datagram(std::move(d));
            } catch (...) {
                if (_stopping) {
                    co_return;
                }
                quic_server_log.error("server receive_loop channel receive failed");
                _stopping = true;
                _accept_cv.broadcast();

                auto conns_copy = _conns;
                for (auto& conn : conns_copy) {
                    conn->fail(quic_error_code::io, "server receive_loop channel receive failed");
                }
                co_return;
            }
        }
    }

    quic_server_config _cfg{};
    gnutls_certificate_credentials_t _cred = nullptr;
    net::datagram_channel _channel{};
    bool _channel_ready = false;
    socket_address _listen_address{};

    bool _started = false;
    bool _stopping = false;

    gate _task_gate;
    condition_variable _accept_cv;
    std::deque<internal::connection_state_ptr> _accepted;
    std::unordered_map<std::string, conn_ptr> _by_dcid;
    std::vector<conn_ptr> _conns;
};

bool server_connection::active() const noexcept {
    return !closing && command_runtime && !server.expired();
}

future<> server_connection::send_datagram_packet(temporary_buffer<char> packet) {
    auto server_state = lock_server();
    if (!server_state) {
        co_return;
    }
    co_await send_datagram(quic_server_log, server_state->channel(), peer, std::move(packet));
}

bool server_connection::can_send_connection_close() const noexcept {
    auto server_state = lock_server();
    return conn && server_state && !server_state->channel().is_closed();
}

future<> server_connection::actor_handle_next_rx_event() {
    auto evt = rx_queue.pop();
    co_await internal::recv_transport_datagram(transport, evt.src, std::move(evt.packet));
    request_blocked_send_retry();
}

future<> server_connection::actor_handle_stop_request() {
    auto self = shared_from_this();
    auto stop_error_local = stop_error;
    auto stop_error_detail_local = stop_error_detail;
    stop_requested = false;
    discard_blocked_send();

    co_await internal::send_connection_close(transport);

    closing = true;
    abort_event_queues(stop_error_local ? "server connection failed" : "server connection stopped");
    if (command_runtime && command_runtime->is_open()) {
        if (stop_error_local) {
            command_runtime->mark_error(*stop_error_local, stop_error_detail_local);
        } else {
            command_runtime->mark_transport_closed();
        }
    }
    if (connection_state) {
        if (stop_error_local) {
            connection_state->on_transport_closed(std::make_exception_ptr(quic_error(*stop_error_local, stop_error_detail_local)));
        } else {
            connection_state->on_transport_closed(std::make_exception_ptr(quic_error(quic_error_code::closed, "server connection stopped")));
        }
    }
    if (auto server_state = lock_server()) {
        server_state->unregister_connection(self);
    }
}

future<> server_connection::actor_handle_timer_tick() {
    co_await internal::handle_transport_timer(transport);
    request_blocked_send_retry();
}

void server_connection::stop_transport() {
    quic_server_log.info("server connection request stop: peer={} closing={} mapped_dcids={}", peer, closing, mapped_dcids.size());
    if (closing || stop_requested) {
        return;
    }
    stop_requested = true;
    fail_blocked_open_streams(quic_error_code::closed, "server connection stopped");
    discard_blocked_send();
    if (connection_state) {
        connection_state->on_transport_closed(std::make_exception_ptr(quic_error(quic_error_code::closed, "server connection stopped")));
    }
    cancel_transport_timer();
    wake_actor();
}

void server_connection::fail(quic_error_code error, const sstring& detail) {
    quic_server_log.error(
      "server connection failure: peer={} error={} detail='{}' closing={} mapped_dcids={}",
      peer,
      to_string(error),
      detail,
      closing,
      mapped_dcids.size());
    if (closing) {
        return;
    }
    if (!stop_error) {
        stop_error = error;
        stop_error_detail = detail;
    }
    fail_blocked_open_streams(error, detail);
    discard_blocked_send();
    if (connection_state) {
        connection_state->on_transport_closed(std::make_exception_ptr(quic_error(error, detail)));
    }
    cancel_transport_timer();
    stop_requested = true;
    wake_actor();
}

void server_connection::fail_transport(quic_error_code error, sstring detail) {
    fail(error, detail);
}

quic_server::quic_server()
    : _impl(std::make_shared<quic_server_impl>()) {
}

quic_server::~quic_server() {
    if (_impl) {
        _impl->request_stop_detached();
    }
}
quic_server::quic_server(quic_server&&) noexcept = default;
quic_server& quic_server::operator=(quic_server&&) noexcept = default;

future<> quic_server::start(quic_server_config config) {
    quic_server_log.debug("quic_server::start");
    co_await _impl->start(std::move(config));
}

future<connection> quic_server::accept() {
    quic_server_log.debug("quic_server::accept");
    auto connection_state = co_await _impl->accept();
    co_return connection(std::make_unique<connection::impl>(std::move(connection_state)));
}

future<> quic_server::stop() {
    quic_server_log.debug("quic_server::stop");
    co_await _impl->stop();
}

} // namespace seastar::quic::experimental
