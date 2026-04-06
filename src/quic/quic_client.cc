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

#include <seastar/quic/quic_client.hh>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <exception>
#include <memory>
#include <optional>
#include <unordered_set>
#include <utility>
#include <vector>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <seastar/core/coroutine.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/gate.hh>
#include <seastar/core/queue.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sleep.hh>
#include <seastar/util/log.hh>

namespace seastar::quic::experimental {

namespace {

constexpr size_t max_udp_payload_size = 65527;
constexpr size_t default_udp_payload_size = 1200;

static logger quic_client_log("quic_client");
using quic_message = internal::quic_message;

struct tls_verification_failure {
    quic_error error = quic_error::none;
    sstring detail;
};

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
    quic_client_log.error("client random source failure: context={} detail='{}'", context, gnutls_error_message(rv));
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

void to_sockaddr_storage(const socket_address& sa, sockaddr_storage& out, socklen_t& outlen) {
    std::memset(&out, 0, sizeof(out));
    switch (sa.family()) {
    case AF_INET: {
        auto in = sa.as_posix_sockaddr_in();
        std::memcpy(&out, &in, sizeof(in));
        outlen = sizeof(in);
        return;
    }
    case AF_INET6: {
        auto in6 = sa.as_posix_sockaddr_in6();
        std::memcpy(&out, &in6, sizeof(in6));
        outlen = sizeof(in6);
        return;
    }
    default:
        throw_quic_error(quic_error::invalid_argument, "QUIC requires an IPv4 or IPv6 socket address");
    }
}

void validate_ip_socket_address(const socket_address& sa, std::string_view what) {
    switch (sa.family()) {
    case AF_INET:
    case AF_INET6:
        return;
    default:
        throw_quic_error(
          quic_error::invalid_argument,
          sstring(what) + " must be an IPv4 or IPv6 socket address");
    }
}

socket_address wildcard_address_for_family(sa_family_t family) {
    switch (family) {
    case AF_INET: {
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        return socket_address(sa);
    }
    case AF_INET6: {
        sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        return socket_address(sa);
    }
    default:
        throw_quic_error(quic_error::invalid_argument, "QUIC requires an IPv4 or IPv6 socket address");
    }
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

temporary_buffer<char> linearize_packet(std::span<temporary_buffer<char>> bufs) {
    size_t total = 0;
    for (const auto& b : bufs) {
        total += b.size();
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

future<> send_datagram(net::datagram_channel& channel, const socket_address& dst, temporary_buffer<char> packet) {
    if (packet.empty()) {
        co_return;
    }
    quic_client_log.trace("udp send datagram: dst={} bytes={}", dst, packet.size());
    std::array<temporary_buffer<char>, 1> bufs{std::move(packet)};
    co_await channel.send(dst, std::span<temporary_buffer<char>>(bufs));
}

struct rx_event {
    socket_address src;
    temporary_buffer<char> packet;
};

struct client_state;
void sync_current_path(client_state& st);

struct client_state : public enable_lw_shared_from_this<client_state>, public internal::connection_transport, public internal::connection_actor {
    quic_client_config cfg{};
    internal::session_runtime_ptr runtime;

    net::datagram_channel channel{};
    bool channel_ready = false;
    socket_address local_address{};
    socket_address remote_address{};

    sockaddr_storage local_ss{};
    socklen_t local_ss_len = 0;
    sockaddr_storage remote_ss{};
    socklen_t remote_ss_len = 0;

    ngtcp2_conn* conn = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};
    gnutls_certificate_credentials_t cred = nullptr;
    gnutls_session_t tls = nullptr;

    gate task_gate;
    queue<std::unique_ptr<rx_event>> rx_queue{1024};
    internal::connection_engine_ptr engine;
    bool queues_aborted = false;
    bool stop_requested = false;
    std::optional<promise<>> handshake_promise;
    bool handshake_promise_resolved = false;

    bool stopping = false;
    bool handshake_done = false;
    size_t tx_payload_limit = default_udp_payload_size;
    temporary_buffer<char> tx_packet_scratch;
    std::optional<internal::transport_command> blocked_send_command;
    bool blocked_send_retry_requested = false;

    ~client_state() {
        fail_blocked_open_streams(quic_error::closed, "client state destroyed");
        discard_blocked_send();
        abort_event_queues("client state destroyed");
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
        if (cred) {
            gnutls_certificate_free_credentials(cred);
            cred = nullptr;
        }
    }

    void fill_path(ngtcp2_path& path) {
        init_ngtcp2_addr(&path.local, reinterpret_cast<sockaddr*>(&local_ss), local_ss_len);
        init_ngtcp2_addr(&path.remote, reinterpret_cast<sockaddr*>(&remote_ss), remote_ss_len);
    }

    bool active() const noexcept {
        return !stopping && runtime;
    }

    bool transport_active() const noexcept override {
        return active();
    }

    bool has_transport_connection() const noexcept override {
        return conn != nullptr;
    }

    bool can_retry_blocked_open_streams() const noexcept override {
        return active() && handshake_done;
    }

    size_t tx_payload_limit_bytes() const noexcept override {
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
               || (runtime && runtime->transport_terminal())
               || !rx_queue.empty()
               || blocked_send_retry_pending()
               || (!has_blocked_send() && runtime && runtime->has_pending_commands())
               || engine->tick_pending()
               || engine->has_blocked_open_stream_retry_work();
    }

    future<> wait_for_actor_wakeup() {
        return engine->wait_for_actor_wakeup(has_pending_actor_work(), stopping);
    }

    void wake_actor() {
        engine->wake_actor();
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
      size_t outbuf_size) override {
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
          now_ns());
        return internal::transport_stream_write_result{
          .nwrite = nwrite,
          .consumed = consumed > 0 ? static_cast<size_t>(consumed) : 0,
        };
    }

    void complete_send_bytes(size_t len) override {
        if (runtime) {
            runtime->complete_send_bytes(len);
        }
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

    int consume_stream_data(stream_id sid, size_t len) override {
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

    int shutdown_stream_read(stream_id sid, application_error_code app_error_code) override {
        return ngtcp2_conn_shutdown_stream_read(conn, 0, sid, app_error_code);
    }

    int read_transport_datagram(const socket_address& src, const char* data, size_t len) override {
        sockaddr_storage remote_ss{};
        socklen_t remote_ss_len = 0;
        to_sockaddr_storage(src, remote_ss, remote_ss_len);

        ngtcp2_path path{};
        init_ngtcp2_addr(&path.local, reinterpret_cast<sockaddr*>(&local_ss), local_ss_len);
        init_ngtcp2_addr(&path.remote, reinterpret_cast<sockaddr*>(&remote_ss), remote_ss_len);
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

    temporary_buffer<char>& tx_packet_buffer() override {
        return tx_packet_scratch;
    }

    future<> send_datagram_packet(temporary_buffer<char> packet) override {
        return send_datagram(channel, remote_address, std::move(packet));
    }

    bool can_send_connection_close() const noexcept override {
        return conn && channel_ready && !channel.is_closed();
    }

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
        engine->rearm_timer_from_expiry(ngtcp2_conn_get_expiry(conn), now_ns(), stopping);
    }

    void request_close() override {
        request_stop();
    }

    void cancel_transport_timer() {
        if (engine) {
            engine->cancel_timer();
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

    void resolve_handshake_ready() {
        if (!handshake_promise || handshake_promise_resolved) {
            return;
        }
        handshake_promise_resolved = true;
        handshake_promise->set_value();
    }

    void fail_handshake(std::exception_ptr ex) {
        if (!handshake_promise || handshake_promise_resolved) {
            return;
        }
        handshake_promise_resolved = true;
        handshake_promise->set_exception(ex);
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

    void defer_blocked_open_stream(internal::transport_command cmd) override {
        engine->defer_blocked_open_stream(std::move(cmd));
    }

    std::optional<internal::transport_command> pop_blocked_open_stream(stream_type type) override {
        return engine->pop_blocked_open_stream(type);
    }

    void request_blocked_open_stream_retry(stream_type type) {
        engine->request_blocked_open_stream_retry(type);
    }

    void defer_blocked_send(internal::transport_command cmd) {
        blocked_send_command = std::move(cmd);
        blocked_send_retry_requested = false;
    }

    std::optional<internal::transport_command> take_blocked_send() {
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
        if (stopping || stop_requested) {
            return;
        }
        stop_requested = true;
        fail_blocked_open_streams(quic_error::closed, "connection closing");
        cancel_transport_timer();
        wake_actor();
    }

    void stop_transport() override {
        quic_client_log.info(
          "client transport stop: local={} remote={} handshake_done={} channel_ready={}",
          local_address,
          remote_address,
          handshake_done,
          channel_ready);
        stopping = true;
        fail_blocked_open_streams(quic_error::closed, "transport stopped");
        discard_blocked_send();
        abort_event_queues("client transport stopped");
        cancel_transport_timer();
        auto ex = std::make_exception_ptr(quic_exception(quic_error::closed, "transport stopped"));
        if (runtime) {
            runtime->mark_transport_closed();
        }
        if (engine) {
            engine->on_transport_closed(ex);
        }
        fail_handshake(std::make_exception_ptr(quic_exception(quic_error::closed, "transport stopped before handshake")));
        wake_actor();
        if (channel_ready && !channel.is_closed()) {
            channel.shutdown_input();
            channel.shutdown_output();
        }
    }

    void fail(quic_error err, const sstring& detail) {
        quic_client_log.error(
          "client transport failure: error={} detail='{}' local={} remote={} handshake_done={}",
          to_string(err),
          detail,
          local_address,
          remote_address,
          handshake_done);
        stopping = true;
        fail_blocked_open_streams(err, detail);
        discard_blocked_send();
        abort_event_queues("client transport failed");
        cancel_transport_timer();
        auto ex = std::make_exception_ptr(quic_exception(err, detail));
        if (runtime) {
            runtime->mark_error(err, detail);
        }
        if (engine) {
            engine->on_transport_closed(ex);
        }
        fail_handshake(ex);
        wake_actor();
        if (channel_ready && !channel.is_closed()) {
            channel.shutdown_input();
            channel.shutdown_output();
        }
    }

    void fail_transport(quic_error err, sstring detail) override {
        fail(err, detail);
    }

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

    future<> actor_handle_stop_request() override {
        co_await internal::send_connection_close(*this);
        stop_transport();
    }

    bool actor_transport_terminal() const noexcept override {
        return runtime && runtime->transport_terminal();
    }

    future<> actor_handle_transport_terminal() override {
        if (!runtime) {
            co_return;
        }
        if (runtime->transport_failed()) {
            fail(runtime->transport_error(), runtime->transport_error_detail());
        } else {
            stop_transport();
        }
        co_return;
    }

    bool actor_has_rx_event() const noexcept override {
        return !rx_queue.empty();
    }

    future<> actor_handle_next_rx_event() override {
        auto evt = rx_queue.pop();
        if (!evt) {
            co_return;
        }
        co_await internal::recv_transport_datagram(*this, evt->src, std::move(evt->packet));
        request_blocked_send_retry();
    }

    bool actor_has_transport_command() const noexcept override {
        return blocked_send_retry_pending()
               || (!has_blocked_send() && runtime && runtime->has_pending_commands());
    }

    future<> actor_handle_next_transport_command() override {
        std::optional<internal::transport_command> cmd;
        if (blocked_send_retry_pending()) {
            clear_blocked_send_retry();
            cmd = take_blocked_send();
        } else if (!has_blocked_send() && runtime) {
            cmd = runtime->poll_command();
        }
        if (!cmd) {
            co_return;
        }
        auto blocked = co_await internal::handle_transport_command(*this, std::move(*cmd));
        if (blocked) {
            defer_blocked_send(std::move(*blocked));
        }
    }

    future<> actor_retry_blocked_open_streams() override {
        if (!handshake_done) {
            co_return;
        }
        co_await internal::retry_blocked_open_streams(*this, stream_type::bidirectional);
        co_await internal::retry_blocked_open_streams(*this, stream_type::unidirectional);
    }

    bool actor_tick_pending() const noexcept override {
        return engine->tick_pending();
    }

    void actor_clear_tick() noexcept override {
        engine->clear_tick();
    }

    future<> actor_handle_timer_tick() override {
        co_await internal::handle_transport_timer(*this);
        request_blocked_send_retry();
    }
};

void sync_current_path(client_state& st) {
    if (!st.conn) {
        return;
    }

    const auto* path = ngtcp2_conn_get_path(st.conn);
    if (!path) {
        return;
    }

    auto local = to_socket_address(path->local);
    auto remote = to_socket_address(path->remote);
    if (!local || !remote) {
        return;
    }

    if (*local == st.local_address && *remote == st.remote_address) {
        return;
    }

    quic_client_log.info("client active path updated: old_local={} old_remote={} new_local={} new_remote={}",
      st.local_address,
      st.remote_address,
      *local,
      *remote);

    st.local_address = *local;
    st.remote_address = *remote;
    to_sockaddr_storage(st.local_address, st.local_ss, st.local_ss_len);
    to_sockaddr_storage(st.remote_address, st.remote_ss, st.remote_ss_len);
}

ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<ngtcp2_conn*>(ref->user_data);
}

void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
    if (!rand_bytes_or_log(dest, destlen, "ngtcp2 rand callback")) {
        std::terminate();
    }
}

int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void*) {
    cid->datalen = cidlen;
    if (!rand_bytes_or_log(cid->data, cidlen, "connection id generation")) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (!rand_bytes_or_log(token, NGTCP2_STATELESS_RESET_TOKENLEN, "stateless reset token generation")) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t* data, void*) {
    if (!rand_bytes_or_log(data, 8, "path challenge generation")) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

sstring selected_alpn_or_empty(gnutls_session_t tls) {
    gnutls_datum_t selected{};
    if (gnutls_alpn_get_selected_protocol(tls, &selected) != 0 || !selected.data) {
        return {};
    }
    return {reinterpret_cast<const char*>(selected.data), selected.size};
}

static sstring certificate_status_to_string(gnutls_session_t tls, unsigned int status) {
    gnutls_datum_t out{};
    auto rv = gnutls_certificate_verification_status_print(
      status, gnutls_certificate_type_get(tls), &out, 0);
    if (rv < 0) {
        return sstring("certificate verification failed");
    }
    sstring message(reinterpret_cast<const char*>(out.data), out.size);
    gnutls_free(out.data);
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) {
        message.resize(message.size() - 1);
    }
    return message;
}

static std::optional<tls_verification_failure> verify_tls_peer_certificate(client_state& st) {
    unsigned int status = 0;
    auto* hostname = st.cfg.server_name.empty() ? nullptr : st.cfg.server_name.c_str();
    int rv = gnutls_certificate_verify_peers3(st.tls, hostname, &status);
    if (rv < 0) {
        return tls_verification_failure{
          .error = classify_gnutls_error(rv),
          .detail = sstring("peer certificate verification failed: ") + gnutls_error_message(rv),
        };
    }
    if (status != 0) {
        return tls_verification_failure{
          .error = quic_error::protocol,
          .detail = sstring("peer certificate verification failed: ")
                    + certificate_status_to_string(st.tls, status),
        };
    }
    return std::nullopt;
}

int handshake_completed_cb(ngtcp2_conn*, void* user_data) {
    auto* st = static_cast<client_state*>(user_data);
    if (auto verification_failure = verify_tls_peer_certificate(*st)) {
        quic_client_log.warn(
          "client handshake verification failed: error={} detail='{}'",
          to_string(verification_failure->error),
          verification_failure->detail);
        st->fail(verification_failure->error, verification_failure->detail);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    st->handshake_done = true;
    sync_current_path(*st);
    st->runtime->mark_transport_ready(st->local_address, st->remote_address, selected_alpn_or_empty(st->tls));
    st->resolve_handshake_ready();
    quic_client_log.info("client handshake completed");

    st->wake_actor();
    st->rearm_transport_timer();
    return 0;
}

int begin_path_validation_cb(ngtcp2_conn*, uint32_t, const ngtcp2_path* path, const ngtcp2_path*, void* user_data) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st || !path) {
        return 0;
    }

    auto remote = to_socket_address(path->remote);
    if (remote) {
        quic_client_log.info("client begin path validation: current_remote={} candidate_remote={}",
          st->remote_address,
          *remote);
    }
    return 0;
}

int path_validation_cb(
  ngtcp2_conn*,
  uint32_t,
  const ngtcp2_path* path,
  const ngtcp2_path* fallback_path,
  ngtcp2_path_validation_result res,
  void* user_data) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st) {
        return 0;
    }

    auto candidate = path ? to_socket_address(path->remote) : std::nullopt;
    auto fallback = fallback_path ? to_socket_address(fallback_path->remote) : std::nullopt;
    quic_client_log.info("client path validation complete: result={} candidate_remote={} fallback_remote={}",
      res == NGTCP2_PATH_VALIDATION_RESULT_SUCCESS ? "success" : "failure",
      candidate.value_or(socket_address{}),
      fallback.value_or(socket_address{}));

    sync_current_path(*st);
    return 0;
}

int recv_stream_data_cb(ngtcp2_conn* conn, uint32_t flags, int64_t sid, uint64_t, const uint8_t* data, size_t datalen, void* user_data, void*) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st->engine || !st->engine->is_open()) {
        quic_client_log.trace("client drop recv_stream_data: sid={} bytes={} engine_open={}", sid, datalen, st->engine && st->engine->is_open());
        return 0;
    }
    quic_client_log.trace("client recv_stream_data: sid={} bytes={}", sid, datalen);
    auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
    auto peer_initiated = !ngtcp2_conn_is_local_stream(conn, sid);
    temporary_buffer<char> tb(datalen);
    if (datalen) {
        std::memcpy(tb.get_write(), data, datalen);
    }
    st->engine->on_stream_data(sid, type, peer_initiated, std::move(tb), (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
    return 0;
}

int stream_reset_cb(ngtcp2_conn* conn, int64_t sid, uint64_t, uint64_t app_error_code, void* user_data, void*) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st->engine) {
        return 0;
    }
    auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
    auto peer_initiated = !ngtcp2_conn_is_local_stream(conn, sid);
    st->engine->on_stream_reset(sid, type, peer_initiated, app_error_code);
    return 0;
}

int stream_stop_sending_cb(ngtcp2_conn* conn, int64_t sid, uint64_t app_error_code, void* user_data, void*) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st->engine) {
        return 0;
    }
    auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
    auto peer_initiated = !ngtcp2_conn_is_local_stream(conn, sid);
    st->engine->on_stream_stop_sending(sid, type, peer_initiated, app_error_code, internal::stream_shutdown_side::write);
    return 0;
}

int stream_close_cb(ngtcp2_conn*, uint32_t, int64_t sid, uint64_t, void* user_data, void*) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st || !st->engine) {
        return 0;
    }

    st->engine->on_stream_closed(sid);
    return 0;
}

int extend_max_local_streams_bidi_cb(ngtcp2_conn*, uint64_t max_streams, void* user_data) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st) {
        return 0;
    }
    quic_client_log.debug("client local bidi stream capacity extended: max_streams={}", max_streams);
    st->request_blocked_open_stream_retry(stream_type::bidirectional);
    return 0;
}

int extend_max_local_streams_uni_cb(ngtcp2_conn*, uint64_t max_streams, void* user_data) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st) {
        return 0;
    }
    quic_client_log.debug("client local uni stream capacity extended: max_streams={}", max_streams);
    st->request_blocked_open_stream_retry(stream_type::unidirectional);
    return 0;
}

void init_tls(client_state& st) {
    quic_client_log.debug(
      "client init_tls: server_name='{}' alpn_count={}",
      st.cfg.server_name,
      st.cfg.alpns.size());
    int rv = gnutls_certificate_allocate_credentials(&st.cred);
    if (rv < 0) {
        throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
    }

    rv = gnutls_certificate_set_x509_system_trust(st.cred);
    if (rv < 0) {
        throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
    }
    if (st.cfg.ca_file) {
        rv = gnutls_certificate_set_x509_trust_file(st.cred, st.cfg.ca_file->c_str(), GNUTLS_X509_FMT_PEM);
        if (rv < 0) {
            throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
        }
        if (rv == 0) {
            throw quic_exception(
              quic_error::invalid_argument,
              sstring("no trust anchors loaded from ") + *st.cfg.ca_file);
        }
    }

    rv = gnutls_init(&st.tls, GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA);
    if (rv < 0) {
        throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
    }

    rv = gnutls_credentials_set(st.tls, GNUTLS_CRD_CERTIFICATE, st.cred);
    if (rv < 0) {
        throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
    }

    rv = gnutls_priority_set_direct(st.tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr);
    if (rv < 0) {
        throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
    }

    std::vector<gnutls_datum_t> alpns;
    alpns.reserve(st.cfg.alpns.size());
    for (const auto& alpn : st.cfg.alpns) {
        alpns.push_back(gnutls_datum_t{
          reinterpret_cast<unsigned char*>(const_cast<char*>(alpn.data())),
          static_cast<unsigned int>(alpn.size()),
        });
    }
    if (!alpns.empty()) {
        rv = gnutls_alpn_set_protocols(st.tls, alpns.data(), alpns.size(), 0);
        if (rv < 0) {
            throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
        }
    }

    if (!st.cfg.server_name.empty()) {
        rv = gnutls_server_name_set(
          st.tls, GNUTLS_NAME_DNS, st.cfg.server_name.c_str(), st.cfg.server_name.size());
        if (rv < 0) {
            throw quic_exception(classify_gnutls_error(rv), gnutls_error_message(rv));
        }
    }

    rv = ngtcp2_crypto_gnutls_configure_client_session(st.tls);
    if (rv != 0) {
        throw quic_exception(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
    }

    st.conn_ref.get_conn = get_conn;
    st.conn_ref.user_data = nullptr;
    gnutls_session_set_ptr(st.tls, &st.conn_ref);
    quic_client_log.debug("client TLS initialized");
}

ngtcp2_cid random_cid(size_t len) {
    ngtcp2_cid cid{};
    cid.datalen = len;
    rand_bytes_or_throw(cid.data, len, "connection id generation");
    return cid;
}

void init_client_connection(client_state& st) {
    ngtcp2_callbacks callbacks{};
    callbacks.client_initial = ngtcp2_crypto_client_initial_cb;
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
    callbacks.recv_stream_data = recv_stream_data_cb;
    callbacks.stream_close = stream_close_cb;
    callbacks.stream_reset = stream_reset_cb;
    callbacks.stream_stop_sending = stream_stop_sending_cb;
    callbacks.extend_max_local_streams_bidi = extend_max_local_streams_bidi_cb;
    callbacks.extend_max_local_streams_uni = extend_max_local_streams_uni_cb;

    ngtcp2_settings settings{};
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();

    ngtcp2_transport_params params{};
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local =
      st.cfg.session_options.transport.initial_max_stream_data_bidi_local;
    params.initial_max_stream_data_bidi_remote =
      st.cfg.session_options.transport.initial_max_stream_data_bidi_remote;
    params.initial_max_stream_data_uni =
      st.cfg.session_options.transport.initial_max_stream_data_uni;
    params.initial_max_data = st.cfg.session_options.transport.initial_max_data;
    params.initial_max_streams_bidi = st.cfg.session_options.transport.initial_max_streams_bidi;
    params.initial_max_streams_uni = st.cfg.session_options.transport.initial_max_streams_uni;
    params.max_idle_timeout = st.cfg.session_options.transport.max_idle_timeout_ns;
    params.disable_active_migration = 1;

    auto dcid = random_cid(8);
    auto scid = random_cid(8);

    ngtcp2_path path{};
    st.fill_path(path);

    int rv = ngtcp2_conn_client_new(
      &st.conn,
      &dcid,
      &scid,
      &path,
      NGTCP2_PROTO_VER_V1,
      &callbacks,
      &settings,
      &params,
      ngtcp2_mem_for_thread(),
      &st);
    if (rv != 0) {
        throw quic_exception(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
    }

    ngtcp2_conn_set_tls_native_handle(st.conn, st.tls);
    st.conn_ref.user_data = st.conn;

    auto payload = ngtcp2_conn_get_path_max_tx_udp_payload_size(st.conn);
    if (payload == 0) {
        payload = default_udp_payload_size;
    }
    if (payload > max_udp_payload_size) {
        payload = max_udp_payload_size;
    }
    st.tx_payload_limit = payload;
    quic_client_log.info(
      "client QUIC connection initialized: local={} remote={} tx_payload_limit={}",
      st.local_address,
      st.remote_address,
      st.tx_payload_limit);
}

future<> flush_pending_packets_actor(lw_shared_ptr<client_state> st) {
    co_await internal::flush_pending_transport_packets(*st);
}

    future<> recv_loop(lw_shared_ptr<client_state> st) {
    while (st->active()) {
        net::datagram d(std::unique_ptr<net::datagram_impl>{});
        try {
            d = co_await st->channel.receive();
        } catch (...) {
            if (st->stopping || !st->runtime->is_open()) {
                co_return;
            }
            quic_client_log.error("client recv_loop datagram receive failed");
            st->fail(quic_error::io, "datagram receive failed");
            co_return;
        }

        auto src = d.get_src();
        auto pkt = linearize_packet(d.get_buffers());
        quic_client_log.trace("client recv_loop datagram: src={} bytes={}", src, pkt.size());

        try {
            auto evt = std::make_unique<rx_event>(rx_event{src, std::move(pkt)});
            co_await st->rx_queue.push_eventually(std::move(evt));
            st->wake_actor();
        } catch (...) {
            if (st->stopping || !st->runtime || !st->runtime->is_open()) {
                co_return;
            }
            st->fail(quic_error::io, "rx queue push failed");
            co_return;
        }
    }
}

future<> actor_loop(lw_shared_ptr<client_state> st) {
    co_await internal::run_connection_actor(*st);
}

void start_background_tasks(const lw_shared_ptr<client_state>& st) {
    quic_client_log.debug("client starting background tasks");
    (void)with_gate(st->task_gate, [st] { return actor_loop(st); })
      .handle_exception([st](std::exception_ptr) {
          if (st->active()) {
              st->fail(quic_error::io, "actor loop failed");
          }
      })
      .or_terminate();
    (void)with_gate(st->task_gate, [st] { return recv_loop(st); })
      .handle_exception([st](std::exception_ptr) {
          if (st->active()) {
              st->fail(quic_error::io, "receive loop failed");
          }
      })
      .or_terminate();
}

class quic_client_impl {
public:
    future<internal::connection_engine_ptr> connect(quic_client_config config) {
        if (_state) {
            throw_quic_error(quic_error::invalid_state, "client is already connected");
        }
        ensure_gnutls_global();
        quic_client_log.info(
          "client connect start: remote={} local={} server_name='{}' alpn_count={}",
          config.remote_address,
          config.local_address.value_or(wildcard_address_for_family(config.remote_address.family())),
          config.server_name,
          config.alpns.size());

        auto st = make_lw_shared<client_state>();
        st->cfg = std::move(config);
        st->runtime = internal::make_session_runtime(st->cfg.session_options);
        st->engine = internal::make_connection_engine(st->runtime, st->cfg.session_options);
        st->runtime->set_command_notifier([raw = st.get()] {
            raw->wake_actor();
        });
        st->remote_address = st->cfg.remote_address;
        st->handshake_promise.emplace();

        std::exception_ptr init_error;
        try {
            validate_ip_socket_address(st->remote_address, "remote_address");
            auto local = st->cfg.local_address.value_or(wildcard_address_for_family(st->remote_address.family()));
            validate_ip_socket_address(local, "local_address");
            if (local.family() != st->remote_address.family()) {
                throw_quic_error(
                  quic_error::invalid_argument,
                  "local_address and remote_address must use the same address family");
            }
            st->channel = engine().net().make_bound_datagram_channel(local);
            st->channel_ready = true;
            st->local_address = st->channel.local_address();

            to_sockaddr_storage(st->local_address, st->local_ss, st->local_ss_len);
            to_sockaddr_storage(st->remote_address, st->remote_ss, st->remote_ss_len);

            init_tls(*st);
            init_client_connection(*st);

            co_await flush_pending_packets_actor(st);
            st->rearm_transport_timer();

            start_background_tasks(st);
            co_await st->handshake_promise->get_future();
            _state = st;
            quic_client_log.info(
              "client connect initialized: local={} remote={} tx_payload_limit={} alpn='{}'",
              st->local_address,
              st->remote_address,
              st->tx_payload_limit,
              st->runtime->selected_alpn());
        } catch (const quic_exception& e) {
            quic_client_log.error("client connect failed: code={} detail='{}'", to_string(e.code()), e.what());
            init_error = std::current_exception();
        } catch (...) {
            quic_client_log.error("client connect failed: unexpected exception");
            init_error = std::current_exception();
        }

        if (init_error) {
            st->stop_transport();
            co_await st->task_gate.close();
            std::rethrow_exception(init_error);
        }

        co_return st->engine;
    }

    future<> stop() {
        if (!_state) {
            quic_client_log.debug("client stop ignored: not connected");
            co_return;
        }
        auto st = std::exchange(_state, {});
        quic_client_log.info("client stop start: local={} remote={}", st->local_address, st->remote_address);
        st->request_stop();
        co_await st->task_gate.close();
        if (st->channel_ready && !st->channel.is_closed()) {
            st->channel.close();
        }
        quic_client_log.info("client stop complete");
    }

private:
    lw_shared_ptr<client_state> _state;
};

} // namespace

class quic_client::impl final : public quic_client_impl {
};

quic_client::quic_client()
    : _impl(std::make_unique<impl>()) {
}

quic_client::~quic_client() = default;
quic_client::quic_client(quic_client&&) noexcept = default;
quic_client& quic_client::operator=(quic_client&&) noexcept = default;

future<connection> quic_client::connect(quic_client_config config) {
    quic_client_log.debug("quic_client::connect");
    auto engine = co_await _impl->connect(std::move(config));
    co_return connection(std::move(engine));
}

future<> quic_client::stop() {
    quic_client_log.debug("quic_client::stop");
    co_await _impl->stop();
}

} // namespace seastar::quic::experimental
