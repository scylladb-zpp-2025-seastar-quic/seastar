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

#include <algorithm>
#include <array>
#include <chrono>
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
constexpr size_t default_max_tx_udp_payload_size = 1452;
constexpr size_t max_tx_packet_pool_size = 128;

static logger quic_server_log("quic_server");
using transport_command = internal::transport_command;
using quic_message = internal::quic_message;

class gnutls_global_guard {
public:
    gnutls_global_guard() {
        gnutls_global_init();
    }
    ~gnutls_global_guard() {
        gnutls_global_deinit();
    }
};

void ensure_gnutls_global() {
    static gnutls_global_guard guard;
}

ngtcp2_tstamp now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

int try_rand_bytes(uint8_t* dst, size_t len) noexcept {
    return gnutls_rnd(GNUTLS_RND_RANDOM, dst, len);
}

[[noreturn]] void throw_random_failure(const char* context, int rv) {
    throw quic_exception(
      classify_gnutls_error(rv),
      sstring(context) + ": " + gnutls_error_message(rv));
}

void rand_bytes_or_throw(uint8_t* dst, size_t len, const char* context) {
    auto rv = try_rand_bytes(dst, len);
    if (rv < 0) {
        throw_random_failure(context, rv);
    }
}

bool rand_bytes_or_log(uint8_t* dst, size_t len, const char* context) noexcept {
    auto rv = try_rand_bytes(dst, len);
    if (rv >= 0) {
        return true;
    }
    quic_server_log.error("server random source failure: context={} detail='{}'", context, gnutls_error_message(rv));
    return false;
}

void* mem_malloc(size_t size, void*) {
    return std::malloc(size);
}

void mem_free(void* ptr, void*) {
    std::free(ptr);
}

void* mem_calloc(size_t n, size_t s, void*) {
    return std::calloc(n, s);
}

void* mem_realloc(void* ptr, size_t s, void*) {
    return std::realloc(ptr, s);
}

size_t normalize_udp_payload_size(size_t requested, size_t fallback) noexcept {
    auto value = requested == 0 ? fallback : requested;
    if (value < default_udp_payload_size) {
        return default_udp_payload_size;
    }
    if (value > max_udp_payload_size) {
        return max_udp_payload_size;
    }
    return value;
}

ngtcp2_cc_algo to_ngtcp2_cc_algo(congestion_control_algorithm algo) noexcept {
    switch (algo) {
    case congestion_control_algorithm::reno:
        return NGTCP2_CC_ALGO_RENO;
    case congestion_control_algorithm::bbr:
        return NGTCP2_CC_ALGO_BBR;
    case congestion_control_algorithm::cubic:
    default:
        return NGTCP2_CC_ALGO_CUBIC;
    }
}

const ngtcp2_mem* ngtcp2_mem_for_thread() {
    thread_local const ngtcp2_mem mem = {
      nullptr,
      mem_malloc,
      mem_free,
      mem_calloc,
      mem_realloc,
    };
    return &mem;
}

void init_ngtcp2_addr(ngtcp2_addr* addr, const sockaddr* sa, size_t len) {
    addr->addr = const_cast<sockaddr*>(sa);
    addr->addrlen = static_cast<socklen_t>(len);
}

void to_sockaddr_storage_v6(const socket_address& sa, sockaddr_storage& out, socklen_t& outlen) {
    std::memset(&out, 0, sizeof(out));
    auto in6 = sa.as_posix_sockaddr_in6();
    std::memcpy(&out, &in6, sizeof(in6));
    outlen = sizeof(in6);
}

std::optional<socket_address> to_socket_address(const ngtcp2_addr& addr) {
    if (!addr.addr || addr.addrlen == 0) {
        return std::nullopt;
    }

    auto* sa = reinterpret_cast<const sockaddr*>(addr.addr);
    switch (sa->sa_family) {
    case AF_INET: {
        if (addr.addrlen < sizeof(sockaddr_in)) {
            return std::nullopt;
        }
        sockaddr_in in{};
        std::memcpy(&in, sa, sizeof(in));
        return socket_address(in);
    }
    case AF_INET6: {
        if (addr.addrlen < sizeof(sockaddr_in6)) {
            return std::nullopt;
        }
        sockaddr_in6 in6{};
        std::memcpy(&in6, sa, sizeof(in6));
        return socket_address(in6);
    }
    default:
        return std::nullopt;
    }
}

struct queued_datagram_packet {
    temporary_buffer<char> storage;
    size_t size = 0;
};

temporary_buffer<char> linearize_packet(
  std::span<temporary_buffer<char>> bufs,
  internal::transport_debug_stats* stats = nullptr) {
    if (bufs.empty()) {
        return {};
    }
    if (bufs.size() == 1) {
        return std::move(bufs.front());
    }

    size_t total = 0;
    for (const auto& b : bufs) {
        total += b.size();
    }

    if (stats) {
        ++stats->rx_linearized_packets;
        stats->rx_linearized_bytes += total;
    }

    temporary_buffer<char> result(total);
    char* dst = result.get_write();
    size_t offset = 0;
    for (const auto& b : bufs) {
        std::memcpy(dst + offset, b.get(), b.size());
        offset += b.size();
    }
    return result;
}

temporary_buffer<char> copy_or_share_stream_payload(
  temporary_buffer<char>& current_rx_packet,
  const uint8_t* data,
  size_t datalen,
  internal::transport_debug_stats& stats) {
    if (!datalen) {
        return {};
    }

    if (!current_rx_packet.empty()) {
        const auto packet_begin = reinterpret_cast<uintptr_t>(current_rx_packet.get());
        const auto packet_end = packet_begin + current_rx_packet.size();
        const auto data_begin = reinterpret_cast<uintptr_t>(data);
        if (data_begin >= packet_begin && data_begin <= packet_end && datalen <= packet_end - data_begin) {
            return current_rx_packet.share(data_begin - packet_begin, datalen);
        }
    }

    ++stats.rx_fallback_copy_events;
    stats.rx_fallback_copy_bytes += datalen;
    return temporary_buffer<char>(reinterpret_cast<const char*>(data), datalen);
}

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

class quic_server_impl;

struct conn_rx_event {
    socket_address src;
    temporary_buffer<char> packet;
};

struct server_connection;
void sync_current_path(server_connection& conn);

struct server_connection : public enable_lw_shared_from_this<server_connection>, public internal::connection_transport, public internal::connection_actor {
    quic_server_impl* server = nullptr;
    internal::session_runtime_ptr runtime;
    internal::connection_engine_ptr engine;

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
    std::optional<quic_error> stop_error;
    sstring stop_error_detail;

    bool closing = false;
    bool handshake_done = false;
    bool accepted_to_listener = false;
    size_t tx_payload_limit = default_udp_payload_size;
    std::shared_ptr<internal::transport_debug_stats> stats = std::make_shared<internal::transport_debug_stats>();
    bool transport_stats_logged = false;
    std::vector<temporary_buffer<char>> tx_packet_pool;
    std::deque<queued_datagram_packet> tx_datagram_queue;
    std::optional<internal::blocked_send_state> blocked_send;
    temporary_buffer<char> current_rx_packet;
    std::unordered_set<std::string> mapped_dcids;

    ~server_connection() {
        log_transport_stats("destroyed");
        fail_blocked_open_streams(quic_error::closed, "server connection destroyed");
        abort_event_queues("server connection destroyed");
        if (runtime) {
            runtime->set_command_notifier({});
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

    bool transport_active() const noexcept override {
        return active();
    }

    bool has_transport_connection() const noexcept override {
        return conn != nullptr;
    }

    bool can_retry_blocked_open_streams() const noexcept override {
        return active() && !stop_requested;
    }

    size_t tx_payload_limit_bytes() const noexcept override {
        return tx_payload_limit;
    }

    internal::transport_debug_stats& debug_stats() noexcept override {
        return *stats;
    }

    bool has_blocked_send() const noexcept {
        return blocked_send.has_value();
    }

    bool has_pending_actor_work() const noexcept {
        return stop_requested
               || !rx_queue.empty()
               || engine->tick_pending()
               || engine->has_blocked_open_stream_retry_work()
               || (!has_blocked_send() && runtime && runtime->has_pending_commands());
    }

    future<> wait_for_actor_wakeup() {
        return engine->wait_for_actor_wakeup(has_pending_actor_work(), closing);
    }

    void wake_actor() {
        engine->wake_actor();
    }

    temporary_buffer<char> acquire_tx_packet_buffer() override {
        const auto required = tx_payload_limit_bytes();
        while (!tx_packet_pool.empty()) {
            auto packet = std::move(tx_packet_pool.back());
            tx_packet_pool.pop_back();
            if (packet.size() >= required) {
                ++stats->tx_packet_buffer_reuses;
                return packet;
            }
        }
        ++stats->tx_packet_buffer_allocations;
        return temporary_buffer<char>(required);
    }

    int64_t write_pending_packet(uint8_t* outbuf, size_t outbuf_size) override {
        ngtcp2_path path{};
        fill_path(path);
        ngtcp2_pkt_info pkt_info{};
        return ngtcp2_conn_write_pkt(conn, &path, &pkt_info, outbuf, outbuf_size, now_ns());
    }

    internal::transport_stream_write_result write_stream_packet(
      stream_id sid,
      const char* data,
      size_t len,
      bool fin,
      uint8_t* outbuf,
      size_t outbuf_size,
      bool more = false) override {
        ngtcp2_path path{};
        fill_path(path);
        ngtcp2_pkt_info pkt_info{};
        ngtcp2_vec vec{};
        ngtcp2_ssize consumed = 0;
        if (data && len) {
            vec.base = reinterpret_cast<uint8_t*>(const_cast<char*>(data));
            vec.len = len;
        }
        uint32_t flags = 0;
        if (!len && fin) {
            flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
        }
        if (more) {
            flags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
        }
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
          now_ns());
        return internal::transport_stream_write_result{
          .nwrite = nwrite,
          .consumed = consumed > 0 ? static_cast<size_t>(consumed) : 0,
        };
    }

    internal::transport_open_stream_result try_open_stream(stream_type type) override {
        int64_t sid = invalid_stream_id;
        auto rv = type == stream_type::bidirectional
                    ? ngtcp2_conn_open_bidi_stream(conn, &sid, nullptr)
                    : ngtcp2_conn_open_uni_stream(conn, &sid, nullptr);
        return internal::transport_open_stream_result{
          .rv = rv,
          .sid = sid,
        };
    }

    int shutdown_stream_write(stream_id sid, application_error_code app_error_code) override {
        return ngtcp2_conn_shutdown_stream_write(conn, 0, sid, app_error_code);
    }

    int shutdown_stream_read(stream_id sid, application_error_code app_error_code) override {
        return ngtcp2_conn_shutdown_stream_read(conn, 0, sid, app_error_code);
    }

    int read_transport_datagram(const socket_address& src, const char* data, size_t len) override {
        sockaddr_storage peer_addr_ss{};
        socklen_t peer_addr_ss_len = 0;
        to_sockaddr_storage_v6(src, peer_addr_ss, peer_addr_ss_len);

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
          now_ns());
    }

    void sync_transport_path() override {
        sync_current_path(*this);
    }

    uint64_t transport_expiry_ns() const noexcept override {
        return ngtcp2_conn_get_expiry(conn);
    }

    int handle_transport_expiry(uint64_t now_local) override {
        return ngtcp2_conn_handle_expiry(conn, now_local);
    }

    future<> send_datagram_packet(temporary_buffer<char> packet, size_t packet_size) override;

    bool has_queued_datagram_packets() const noexcept override {
        return !tx_datagram_queue.empty();
    }

    future<> flush_datagram_packets() override;

    bool can_send_connection_close() const noexcept override;

    int64_t write_connection_close_packet(uint8_t* outbuf, size_t outbuf_size) override {
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
          now_ns());
    }

    void on_stream_write_closed(stream_id sid) override {
        if (!engine || !conn) {
            return;
        }
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(conn, sid);
        engine->on_stream_stop_sending(sid, type, peer_initiated, 0, internal::stream_shutdown_side::write);
    }

    void rearm_transport_timer() override {
        if (!engine) {
            return;
        }
        if (!conn) {
            engine->cancel_timer();
            return;
        }
        engine->rearm_timer_from_expiry(ngtcp2_conn_get_expiry(conn), now_ns(), closing);
    }

    void request_close() override {
        request_stop();
    }

    void recycle_tx_packet_buffer(temporary_buffer<char> packet) noexcept {
        if (!packet || packet.size() < tx_payload_limit_bytes() || tx_packet_pool.size() >= max_tx_packet_pool_size) {
            return;
        }
        ++stats->tx_packet_buffer_recycles;
        tx_packet_pool.emplace_back(std::move(packet));
    }

    void cancel_transport_timer() {
        if (engine) {
            engine->cancel_timer();
        }
    }

    void log_transport_stats(const char* reason) {
        if (transport_stats_logged || !stats) {
            return;
        }
        transport_stats_logged = true;
        quic_server_log.info(
          "server transport stats: reason={} peer={} tx_payload_limit={} tx_packets={} tx_bytes={} tx_copy_bytes={} tx_copy_events={} tx_blocked_events={} tx_zero_write_events={} tx_packet_buffer_allocations={} tx_packet_buffer_reuses={} tx_packet_buffer_recycles={} rx_packets={} rx_bytes={} rx_linearized_packets={} rx_linearized_bytes={} rx_fallback_copy_events={} rx_fallback_copy_bytes={}",
          reason,
          peer,
          stats->negotiated_tx_payload_limit,
          stats->tx_packets,
          stats->tx_bytes,
          stats->tx_copy_bytes,
          stats->tx_copy_events,
          stats->tx_blocked_events,
          stats->tx_zero_write_events,
          stats->tx_packet_buffer_allocations,
          stats->tx_packet_buffer_reuses,
          stats->tx_packet_buffer_recycles,
          stats->rx_packets,
          stats->rx_bytes,
          stats->rx_linearized_packets,
          stats->rx_linearized_bytes,
          stats->rx_fallback_copy_events,
          stats->rx_fallback_copy_bytes);
    }

    void abort_event_queues(const char* why) {
        if (queues_aborted) {
            return;
        }
        queues_aborted = true;
        auto ex = std::make_exception_ptr(std::runtime_error(why));
        rx_queue.abort(ex);
    }

    void complete_open_stream(std::shared_ptr<promise<stream_id>> result, stream_id sid) override {
        if (runtime) {
            runtime->complete_open_stream(std::move(result), sid);
        }
    }

    void fail_open_stream(
      std::shared_ptr<promise<stream_id>> result,
      quic_error error,
      sstring detail) override {
        if (runtime) {
            runtime->fail_open_stream(std::move(result), error, std::move(detail));
        }
    }

    bool blocked_open_stream_retry_pending(stream_type type) const noexcept override {
        return engine->blocked_open_stream_retry_pending(type);
    }

    void defer_blocked_open_stream(transport_command cmd) override {
        engine->defer_blocked_open_stream(std::move(cmd));
    }

    std::optional<transport_command> pop_blocked_open_stream(stream_type type) override {
        return engine->pop_blocked_open_stream(type);
    }

    void request_blocked_open_stream_retry(stream_type type) {
        engine->request_blocked_open_stream_retry(type);
    }

    void clear_blocked_open_stream_retry(stream_type type) noexcept override {
        engine->clear_blocked_open_stream_retry(type);
    }

    void fail_blocked_open_streams(quic_error error, std::string_view detail) {
        if (!engine) {
            return;
        }
        engine->fail_blocked_open_streams(error, detail);
    }

    void request_stop() {
        if (closing || stop_requested) {
            return;
        }
        stop_requested = true;
        fail_blocked_open_streams(quic_error::closed, "server connection stopping");
        cancel_transport_timer();
        wake_actor();
    }

    bool active() const noexcept;
    bool actor_active() const noexcept override {
        return active();
    }
    bool actor_has_pending_work() const noexcept override {
        return has_pending_actor_work();
    }
    future<> actor_wait_for_wakeup() override {
        return wait_for_actor_wakeup();
    }
    bool actor_stop_requested() const noexcept override {
        return stop_requested;
    }
    future<> actor_handle_stop_request() override;
    bool actor_has_rx_event() const noexcept override {
        return !rx_queue.empty();
    }
    future<> actor_handle_next_rx_event() override;
    bool actor_has_blocked_send() const noexcept override {
        return has_blocked_send();
    }
    void actor_defer_blocked_send(internal::blocked_send_state state) override {
        blocked_send = std::move(state);
    }
    future<> actor_handle_blocked_send() override {
        if (!blocked_send) {
            co_return;
        }
        auto state = std::move(*blocked_send);
        blocked_send.reset();
        co_await internal::send_stream_message(*this, *this, std::move(state));
    }
    bool actor_has_transport_command() const noexcept override {
        return !has_blocked_send() && runtime && runtime->has_pending_commands();
    }
    future<> actor_handle_next_transport_command() override {
        if (!runtime) {
            co_return;
        }
        auto cmd = runtime->poll_command();
        if (!cmd) {
            co_return;
        }
        co_await internal::handle_transport_command(*this, *this, std::move(*cmd));
    }
    future<> actor_retry_blocked_open_streams() override {
        co_await internal::retry_blocked_open_streams(*this, stream_type::bidirectional);
        co_await internal::retry_blocked_open_streams(*this, stream_type::unidirectional);
    }
    bool actor_tick_pending() const noexcept override {
        return engine->tick_pending();
    }
    void actor_clear_tick() noexcept override {
        engine->clear_tick();
    }
    future<> actor_handle_timer_tick() override;
    void stop_transport() override;
    void fail(quic_error error, const sstring& detail);
    void fail_transport(quic_error error, sstring detail) override;
};

using conn_ptr = lw_shared_ptr<server_connection>;

void sync_current_path(server_connection& conn) {
    if (!conn.conn) {
        return;
    }

    const auto* path = ngtcp2_conn_get_path(conn.conn);
    if (!path) {
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

    if ((!old_local || *local == *old_local) && *remote == conn.peer) {
        return;
    }

    quic_server_log.info("server active path updated: old_local={} old_remote={} new_local={} new_remote={}",
      old_local.value_or(socket_address{}),
      conn.peer,
      *local,
      *remote);

    conn.peer = *remote;
    to_sockaddr_storage_v6(*local, conn.local_ss, conn.local_ss_len);
    to_sockaddr_storage_v6(conn.peer, conn.peer_ss, conn.peer_ss_len);
}

class quic_server_impl {
public:
    future<> start(quic_server_config cfg) {
        if (_started) {
            throw_quic_error(quic_error::invalid_state, "server already started");
        }
        ensure_gnutls_global();
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

        (void)with_gate(_task_gate, [this] { return receive_loop(); })
          .handle_exception([this](std::exception_ptr) {
              if (!_stopping) {
                  quic_server_log.error("server receive loop failed");
                  _stopping = true;
                  _accept_cv.signal();
              }
          })
          .or_terminate();
        co_return;
    }

    future<internal::connection_engine_ptr> accept() {
        if (!_started) {
            throw_quic_error(quic_error::invalid_state, "server is not started");
        }
        quic_server_log.debug("server accept wait: pending_accepted={} active_conns={}", _accepted.size(), _conns.size());

        while (_accepted.empty()) {
            if (_stopping) {
                throw_quic_error(quic_error::closed, "server stopped");
            }
            co_await _accept_cv.wait();
        }

        auto engine = std::move(_accepted.front());
        _accepted.pop_front();
        quic_server_log.info("server accept ready: pending_accepted={} active_conns={}", _accepted.size(), _conns.size());
        co_return engine;
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
        _stopping = true;
        _accept_cv.signal();

        auto conns_copy = _conns;
        for (auto& conn : conns_copy) {
            conn->stop_transport();
        }

        if (_channel_ready && !_channel.is_closed()) {
            _channel.shutdown_input();
        }

        co_await _task_gate.close();

        if (_channel_ready && !_channel.is_closed()) {
            _channel.shutdown_output();
            _channel.close();
        }

        _conns.clear();
        _by_dcid.clear();
        _accepted.clear();
        if (_cred) {
            gnutls_certificate_free_credentials(_cred);
            _cred = nullptr;
        }

        _started = false;
        _stopping = false;
        _channel_ready = false;
        quic_server_log.info("server stop complete");
    }

    bool stopping() const noexcept {
        return _stopping;
    }

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

    void enqueue_accepted_session(const internal::connection_engine_ptr& engine) {
        _accepted.push_back(engine);
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
    friend struct server_connection;

    static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref) {
        return static_cast<ngtcp2_conn*>(ref->user_data);
    }

    static void rand_cb(uint8_t* dest, size_t len, const ngtcp2_rand_ctx*) {
        if (!rand_bytes_or_log(dest, len, "ngtcp2 rand callback")) {
            std::terminate();
        }
    }

    static int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void*) {
        cid->datalen = cidlen;
        if (!rand_bytes_or_log(cid->data, cidlen, "connection id generation")) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (!rand_bytes_or_log(token, NGTCP2_STATELESS_RESET_TOKENLEN, "stateless reset token generation")) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        return 0;
    }

    static int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t* data, void*) {
        if (!rand_bytes_or_log(data, 8, "path challenge generation")) {
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
        if (!conn || !conn->runtime) {
            return 0;
        }
        conn->handshake_done = true;
        sync_current_path(*conn);
        conn->runtime->mark_transport_ready(
          to_socket_address(ngtcp2_conn_get_path(conn->conn)->local).value_or(
            conn->server ? conn->server->listen_address() : socket_address{}),
          conn->peer,
          selected_alpn_or_empty(conn->tls));
        if (!conn->accepted_to_listener && conn->server && conn->engine) {
            conn->accepted_to_listener = true;
            conn->server->enqueue_accepted_session(conn->engine);
        }
        quic_server_log.info("server handshake completed: peer={} alpn='{}'", conn->peer, conn->runtime->selected_alpn());
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
        if (!conn || !conn->server || !cid) {
            return 0;
        }
        auto self = conn->shared_from_this();
        if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE) {
            quic_server_log.debug("server dcid activate: peer={} len={}", conn->peer, cid->datalen);
            conn->server->map_dcid(self, cid->data, cid->datalen);
        } else if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE) {
            quic_server_log.debug("server dcid deactivate: peer={} len={}", conn->peer, cid->datalen);
            conn->server->unmap_dcid(self, cid->data, cid->datalen);
        }
        return 0;
    }

    static int recv_stream_data_cb(ngtcp2_conn* ngconn, uint32_t flags, int64_t sid, uint64_t, const uint8_t* data, size_t datalen, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->engine || !conn->engine->is_open()) {
            quic_server_log.trace("server drop recv_stream_data: sid={} bytes={} conn_valid={} engine_open={}",
              sid, datalen, conn != nullptr, conn && conn->engine && conn->engine->is_open());
            return 0;
        }
        quic_server_log.trace("server recv_stream_data: peer={} sid={} bytes={}", conn->peer, sid, datalen);
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(ngconn, sid);
        auto tb = copy_or_share_stream_payload(conn->current_rx_packet, data, datalen, *conn->stats);
        conn->engine->on_stream_data(sid, type, peer_initiated, std::move(tb), (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
        ngtcp2_conn_extend_max_stream_offset(ngconn, sid, datalen);
        ngtcp2_conn_extend_max_offset(ngconn, datalen);
        return 0;
    }

    static int stream_reset_cb(ngtcp2_conn* ngconn, int64_t sid, uint64_t, uint64_t app_error_code, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->engine) {
            return 0;
        }
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(ngconn, sid);
        conn->engine->on_stream_reset(sid, type, peer_initiated, app_error_code);
        return 0;
    }

    static int stream_stop_sending_cb(ngtcp2_conn* ngconn, int64_t sid, uint64_t app_error_code, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->engine) {
            return 0;
        }
        auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
        auto peer_initiated = !ngtcp2_conn_is_local_stream(ngconn, sid);
        conn->engine->on_stream_stop_sending(sid, type, peer_initiated, app_error_code, internal::stream_shutdown_side::write);
        return 0;
    }

    static int stream_close_cb(ngtcp2_conn* ngconn, uint32_t, int64_t sid, uint64_t, void* user_data, void*) {
        auto* conn = static_cast<server_connection*>(user_data);
        if (!conn || !conn->engine || !ngconn) {
            return 0;
        }

        conn->engine->on_stream_closed(sid);

        if (ngtcp2_conn_is_local_stream(ngconn, sid)) {
            return 0;
        }

        if (ngtcp2_is_bidi_stream(sid)) {
            ngtcp2_conn_extend_max_streams_bidi(ngconn, 1);
        } else {
            ngtcp2_conn_extend_max_streams_uni(ngconn, 1);
        }
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
        conn->server = this;
        conn->runtime = internal::make_session_runtime(_cfg.session_options);
        conn->engine = internal::make_connection_engine(conn->runtime, _cfg.session_options, conn->stats);
        conn->runtime->set_command_notifier([raw = conn.get()] {
            raw->wake_actor();
        });
        conn->peer = peer;
        to_sockaddr_storage_v6(_listen_address, conn->local_ss, conn->local_ss_len);
        to_sockaddr_storage_v6(peer, conn->peer_ss, conn->peer_ss_len);
        conn->tls = make_tls_session(*conn);

        ngtcp2_version_cid vc{};
        int rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, pkt_len, NGTCP2_MAX_CIDLEN);
        if (rv < 0) {
            throw_quic_error(quic_error::protocol, "failed to decode Initial CID");
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
        settings.cc_algo = to_ngtcp2_cc_algo(_cfg.session_options.transport.congestion_control);
        settings.initial_ts = now_ns();
        settings.max_window = _cfg.session_options.transport.max_window;
        settings.max_stream_window = _cfg.session_options.transport.max_stream_window;
        settings.ack_thresh = _cfg.session_options.transport.ack_thresh;
        if (_cfg.session_options.transport.initial_rtt_ns > 0) {
            settings.initial_rtt = _cfg.session_options.transport.initial_rtt_ns;
        }
        settings.max_tx_udp_payload_size = normalize_udp_payload_size(
          _cfg.session_options.transport.max_tx_udp_payload_size,
          default_max_tx_udp_payload_size);
        settings.no_tx_udp_payload_size_shaping =
          _cfg.session_options.transport.disable_tx_udp_payload_size_shaping ? 1 : 0;

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
        params.max_udp_payload_size = normalize_udp_payload_size(
          _cfg.session_options.transport.max_udp_payload_size,
          max_udp_payload_size);
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

        auto payload = ngtcp2_conn_get_path_max_tx_udp_payload_size(conn->conn);
        if (payload == 0) {
            payload = ngtcp2_conn_get_max_tx_udp_payload_size(conn->conn);
        }
        payload = normalize_udp_payload_size(payload, default_udp_payload_size);
        conn->tx_payload_limit = payload;
        conn->stats->negotiated_tx_payload_limit = conn->tx_payload_limit;

        map_dcid(conn, odcid.data, odcid.datalen);
        map_dcid(conn, scid.data, scid.datalen);
        _conns.push_back(conn);
        quic_server_log.info(
          "server connection initialized: peer={} tx_payload_limit={} max_tx_udp_payload_size={} max_udp_payload_size={} tx_payload_shaping_disabled={} active_conns={} odcid_len={} scid_len={}",
          conn->peer,
          conn->tx_payload_limit,
          settings.max_tx_udp_payload_size,
          params.max_udp_payload_size,
          bool(settings.no_tx_udp_payload_size_shaping),
          _conns.size(),
          odcid.datalen,
          scid.datalen);

        (void)with_gate(_task_gate, [conn] { return conn_actor_loop(conn); })
          .handle_exception([conn](std::exception_ptr) {
              conn->closing = true;
              conn->abort_event_queues("server actor loop failed");
              if (conn->runtime && conn->runtime->is_open()) {
                  conn->runtime->mark_error(quic_error::io, "server actor loop failed");
              }
              if (conn->server) {
                  conn->server->unregister_connection(conn);
              }
          })
          .or_terminate();
        return conn;
    }

    static future<> flush_pending_packets_actor(conn_ptr conn) {
        co_await internal::flush_pending_transport_packets(*conn);
        if (conn->has_queued_datagram_packets()) {
            co_await conn->flush_datagram_packets();
        }
    }

    static future<> conn_actor_loop(conn_ptr conn) {
        co_await internal::run_connection_actor(*conn, *conn);
    }

    void handle_datagram(net::datagram d) {
        auto src = d.get_src();
        auto bufs = d.get_buffers();
        const bool was_linearized = bufs.size() > 1;
        auto pkt = linearize_packet(bufs);
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
            if (was_linearized) {
                ++conn->stats->rx_linearized_packets;
                conn->stats->rx_linearized_bytes += len;
            }
            ++conn->stats->rx_packets;
            conn->stats->rx_bytes += len;
            if (!conn->rx_queue.push(conn_rx_event{src, std::move(pkt)})) {
                quic_server_log.warn("server rx queue full: peer={} queued={} max={}", conn->peer, conn->rx_queue.size(), conn->rx_queue.max_size());
                conn->fail(quic_error::io, "server rx queue is full");
                return;
            }
            conn->wake_actor();
        } catch (...) {
            if (!conn->active()) {
                return;
            }
            conn->fail(quic_error::io, "server rx queue push failed");
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
                    conn->fail(quic_error::io, "server receive_loop channel receive failed");
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
    std::deque<internal::connection_engine_ptr> _accepted;
    std::unordered_map<std::string, conn_ptr> _by_dcid;
    std::vector<conn_ptr> _conns;
};

bool server_connection::active() const noexcept {
    return !closing && runtime && runtime->is_open() && server;
}

future<> server_connection::send_datagram_packet(temporary_buffer<char> packet, size_t packet_size) {
    if (packet_size && !packet.empty()) {
        tx_datagram_queue.emplace_back(queued_datagram_packet{
          .storage = std::move(packet),
          .size = packet_size,
        });
    } else {
        recycle_tx_packet_buffer(std::move(packet));
    }
    return make_ready_future<>();
}

future<> server_connection::flush_datagram_packets() {
    if (tx_datagram_queue.empty()) {
        co_return;
    }

    static constexpr size_t max_batch = 64;

    while (!tx_datagram_queue.empty()) {
        temporary_buffer<char> views[max_batch];
        temporary_buffer<char> storages[max_batch];
        size_t count = 0;

        while (!tx_datagram_queue.empty() && count < max_batch) {
            auto packet = std::move(tx_datagram_queue.front());
            tx_datagram_queue.pop_front();
            views[count] = packet.storage.share(0, packet.size);
            ++stats->tx_packets;
            stats->tx_bytes += packet.size;
            storages[count] = std::move(packet.storage);
            ++count;
        }

        co_await server->channel().send_datagrams(peer, std::span<temporary_buffer<char>>(views, count));

        for (size_t i = 0; i < count; ++i) {
            recycle_tx_packet_buffer(std::move(storages[i]));
        }
    }
}

bool server_connection::can_send_connection_close() const noexcept {
    return conn && server && !server->channel().is_closed();
}

future<> server_connection::actor_handle_next_rx_event() {
    if (rx_queue.empty()) {
        co_return;
    }
    auto evt = rx_queue.pop();
    current_rx_packet = evt.packet.share();
    try {
        co_await internal::recv_transport_datagram(*this, evt.src, std::move(evt.packet));
    } catch (...) {
        current_rx_packet = {};
        throw;
    }
    current_rx_packet = {};
}

future<> server_connection::actor_handle_stop_request() {
    auto self = shared_from_this();
    auto stop_error_local = stop_error;
    auto stop_error_detail_local = stop_error_detail;
    stop_requested = false;

    co_await internal::send_connection_close(*this);
    log_transport_stats(stop_error_local ? "failed" : "stopped");

    closing = true;
    abort_event_queues(stop_error_local ? "server connection failed" : "server connection stopped");
    if (runtime && runtime->is_open()) {
        if (stop_error_local) {
            runtime->mark_error(*stop_error_local, stop_error_detail_local);
        } else {
            runtime->mark_transport_closed();
        }
    }
    if (engine) {
        if (stop_error_local) {
            engine->on_transport_closed(std::make_exception_ptr(quic_exception(*stop_error_local, stop_error_detail_local)));
        } else {
            engine->on_transport_closed(std::make_exception_ptr(quic_exception(quic_error::closed, "server connection stopped")));
        }
    }
    if (server) {
        server->unregister_connection(self);
    }
}

future<> server_connection::actor_handle_timer_tick() {
    co_await internal::handle_transport_timer(*this);
}

void server_connection::stop_transport() {
    quic_server_log.info("server connection request stop: peer={} closing={} mapped_dcids={}", peer, closing, mapped_dcids.size());
    if (closing || stop_requested) {
        return;
    }
    stop_requested = true;
    fail_blocked_open_streams(quic_error::closed, "server connection stopped");
    if (engine) {
        engine->on_transport_closed(std::make_exception_ptr(quic_exception(quic_error::closed, "server connection stopped")));
    }
    cancel_transport_timer();
    wake_actor();
}

void server_connection::fail(quic_error error, const sstring& detail) {
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
    if (engine) {
        engine->on_transport_closed(std::make_exception_ptr(quic_exception(error, detail)));
    }
    cancel_transport_timer();
    stop_requested = true;
    wake_actor();
}

void server_connection::fail_transport(quic_error error, sstring detail) {
    fail(error, detail);
}

} // namespace

class quic_server::impl final : public quic_server_impl {
};

quic_server::quic_server()
    : _impl(std::make_unique<impl>()) {
}

quic_server::~quic_server() = default;
quic_server::quic_server(quic_server&&) noexcept = default;
quic_server& quic_server::operator=(quic_server&&) noexcept = default;

future<> quic_server::start(quic_server_config config) {
    quic_server_log.debug("quic_server::start");
    co_await _impl->start(std::move(config));
}

future<connection> quic_server::accept() {
    quic_server_log.debug("quic_server::accept");
    auto engine = co_await _impl->accept();
    co_return connection(std::move(engine));
}

future<> quic_server::stop() {
    quic_server_log.debug("quic_server::stop");
    co_await _impl->stop();
}

} // namespace seastar::quic::experimental
