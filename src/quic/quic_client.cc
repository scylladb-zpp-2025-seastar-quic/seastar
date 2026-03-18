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

void rand_bytes(uint8_t* dst, size_t len) {
    if (gnutls_rnd(GNUTLS_RND_RANDOM, dst, len) == 0) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        dst[i] = static_cast<uint8_t>(std::rand());
    }
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

future<> send_datagram(net::datagram_channel& channel, const socket_address& dst, const uint8_t* data, size_t len) {
    if (len == 0) {
        co_return;
    }
    quic_client_log.trace("udp send datagram: dst={} bytes={}", dst, len);
    temporary_buffer<char> tb(len);
    std::memcpy(tb.get_write(), data, len);
    std::array<temporary_buffer<char>, 1> bufs{std::move(tb)};
    co_await channel.send(dst, std::span<temporary_buffer<char>>(bufs));
}

struct rx_event {
    socket_address src;
    temporary_buffer<char> packet;
};

struct client_state : public enable_lw_shared_from_this<client_state> {
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
    queue<std::unique_ptr<internal::transport_command>> op_queue{1024};
    std::deque<internal::transport_command> pre_handshake_ops;
    std::optional<promise<>> actor_waiter;
    condition_variable timer_cv;
    bool timer_rearm_requested = false;
    bool tick_pending = false;
    bool queues_aborted = false;
    bool stop_requested = false;
    std::optional<promise<>> handshake_promise;
    bool handshake_promise_resolved = false;

    bool stopping = false;
    bool handshake_done = false;
    size_t tx_payload_limit = default_udp_payload_size;
    std::unordered_set<stream_id> announced_streams;

    ~client_state() {
        abort_event_queues("client state destroyed");
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

    bool has_pending_actor_work() const noexcept {
        return stop_requested || !rx_queue.empty() || !op_queue.empty() || tick_pending || (handshake_done && !pre_handshake_ops.empty());
    }

    future<> wait_for_actor_wakeup() {
        if (has_pending_actor_work() || stopping) {
            co_return;
        }
        actor_waiter.emplace();
        try {
            co_await actor_waiter->get_future();
        } catch (...) {
        }
    }

    void wake_actor() {
        if (!actor_waiter) {
            return;
        }
        auto waiter = std::move(*actor_waiter);
        actor_waiter.reset();
        waiter.set_value();
    }

    void signal_tick() {
        if (stopping || tick_pending) {
            return;
        }
        tick_pending = true;
        wake_actor();
    }

    void request_timer_rearm() {
        timer_rearm_requested = true;
        timer_cv.signal();
    }

    void abort_event_queues(const char* why) {
        if (queues_aborted) {
            return;
        }
        queues_aborted = true;
        auto ex = std::make_exception_ptr(std::runtime_error(why));
        rx_queue.abort(ex);
        op_queue.abort(std::move(ex));
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

    void request_stop() {
        if (stopping || stop_requested) {
            return;
        }
        stop_requested = true;
        wake_actor();
        request_timer_rearm();
    }

    void stop_transport() {
        quic_client_log.info(
          "client transport stop: local={} remote={} handshake_done={} channel_ready={}",
          local_address,
          remote_address,
          handshake_done,
          channel_ready);
        stopping = true;
        abort_event_queues("client transport stopped");
        if (runtime) {
            runtime->mark_transport_closed();
        }
        fail_handshake(std::make_exception_ptr(quic_exception(quic_error::closed, "transport stopped before handshake")));
        wake_actor();
        request_timer_rearm();
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
        abort_event_queues("client transport failed");
        if (runtime) {
            runtime->mark_error(err, detail);
        }
        fail_handshake(std::make_exception_ptr(quic_exception(err, detail)));
        wake_actor();
        request_timer_rearm();
        if (channel_ready && !channel.is_closed()) {
            channel.shutdown_input();
            channel.shutdown_output();
        }
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
    to_sockaddr_storage_v6(st.local_address, st.local_ss, st.local_ss_len);
    to_sockaddr_storage_v6(st.remote_address, st.remote_ss, st.remote_ss_len);
}

ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* ref) {
    return static_cast<ngtcp2_conn*>(ref->user_data);
}

void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
    rand_bytes(dest, destlen);
}

int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token, size_t cidlen, void*) {
    cid->datalen = cidlen;
    rand_bytes(cid->data, cidlen);
    rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t* data, void*) {
    rand_bytes(data, 8);
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
    st->request_timer_rearm();
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
    if (!st->runtime || !st->runtime->is_open()) {
        quic_client_log.trace("client drop recv_stream_data: sid={} bytes={} runtime_open={}", sid, datalen, st->runtime && st->runtime->is_open());
        return 0;
    }
    quic_client_log.trace("client recv_stream_data: sid={} bytes={}", sid, datalen);
    auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
    auto peer_initiated = !ngtcp2_conn_is_local_stream(conn, sid);
    if (st->announced_streams.emplace(sid).second) {
        st->runtime->push_event(internal::stream_event{
          .op = internal::stream_event::kind::opened,
          .stream = sid,
          .type = type,
          .peer_initiated = peer_initiated,
        });
    }
    temporary_buffer<char> tb(datalen);
    if (datalen) {
        std::memcpy(tb.get_write(), data, datalen);
    }
    st->runtime->push_event(internal::stream_event{
      .op = internal::stream_event::kind::data,
      .stream = sid,
      .type = type,
      .peer_initiated = peer_initiated,
      .payload = std::move(tb),
      .fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0,
    });
    return 0;
}

int stream_reset_cb(ngtcp2_conn* conn, int64_t sid, uint64_t, uint64_t app_error_code, void* user_data, void*) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st->runtime) {
        return 0;
    }
    auto type = ngtcp2_is_bidi_stream(sid) ? stream_type::bidirectional : stream_type::unidirectional;
    auto peer_initiated = !ngtcp2_conn_is_local_stream(conn, sid);
    st->runtime->push_event(internal::stream_event{
      .op = internal::stream_event::kind::reset,
      .stream = sid,
      .type = type,
      .peer_initiated = peer_initiated,
      .app_error_code = app_error_code,
    });
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
    rand_bytes(cid.data, len);
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
    callbacks.stream_reset = stream_reset_cb;

    ngtcp2_settings settings{};
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();

    ngtcp2_transport_params params{};
    ngtcp2_transport_params_default(&params);
    params.initial_max_stream_data_bidi_local =
      st.cfg.session_options.transport.initial_max_stream_data_bidi_local;
    params.initial_max_stream_data_bidi_remote =
      st.cfg.session_options.transport.initial_max_stream_data_bidi_remote;
    params.initial_max_data = st.cfg.session_options.transport.initial_max_data;
    params.initial_max_streams_bidi = st.cfg.session_options.transport.initial_max_streams_bidi;
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
    if (!st->conn) {
        co_return;
    }

    std::vector<uint8_t> outbuf(st->tx_payload_limit);
    while (st->active()) {
        ngtcp2_path path{};
        st->fill_path(path);
        ngtcp2_pkt_info pkt_info{};

        ngtcp2_ssize nwrite =
          ngtcp2_conn_write_pkt(st->conn, &path, &pkt_info, outbuf.data(), outbuf.size(), now_ns());
        if (nwrite == 0) {
            quic_client_log.trace("client flush_pending_packets: no packet produced");
            co_return;
        }
        if (nwrite < 0) {
            if (ngtcp2_is_write_more(nwrite)) {
                quic_client_log.trace("client flush_pending_packets: write_more");
                continue;
            }
            if (ngtcp2_is_draining(nwrite)) {
                quic_client_log.info("client flush_pending_packets: connection draining");
                st->stop_transport();
                co_return;
            }
            quic_client_log.warn("client flush_pending_packets failed: nwrite={} msg={}", nwrite, ngtcp2_error_message((int)nwrite));
            st->fail(classify_ngtcp2_error(nwrite), ngtcp2_error_message((int)nwrite));
            co_return;
        }
        quic_client_log.trace("client flush_pending_packets: wrote {} bytes", nwrite);
        co_await send_datagram(st->channel, st->remote_address, outbuf.data(), static_cast<size_t>(nwrite));
    }
}

future<> send_stream_message_actor(lw_shared_ptr<client_state> st, quic_message msg) {
    if (!st->conn || msg.stream == invalid_stream_id) {
        co_return;
    }
    quic_client_log.debug(
      "client send_stream_message start: sid={} bytes={} fin={}",
      msg.stream,
      msg.payload.size(),
      msg.fin);
    int64_t sid = msg.stream;
    size_t offset = 0;
    bool send_fin = msg.fin;
    std::vector<uint8_t> outbuf(st->tx_payload_limit);

    while (st->active()) {
        const bool remaining = offset < msg.payload.size();
        if (!remaining && !send_fin) {
            break;
        }

        ngtcp2_path path{};
        st->fill_path(path);
        ngtcp2_pkt_info pkt_info{};
        ngtcp2_vec vec{};
        ngtcp2_ssize consumed = 0;

        const uint8_t* ptr = remaining ? reinterpret_cast<const uint8_t*>(msg.payload.get() + offset) : nullptr;
        const size_t len = remaining ? (msg.payload.size() - offset) : 0;
        if (remaining) {
            vec.base = const_cast<uint8_t*>(ptr);
            vec.len = len;
        }

        uint32_t flags = (!remaining && send_fin) ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
        ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
          st->conn,
          &path,
          &pkt_info,
          outbuf.data(),
          outbuf.size(),
          &consumed,
          flags,
          sid,
          remaining ? &vec : nullptr,
          remaining ? 1 : 0,
          now_ns());

        if (nwrite < 0) {
            if (ngtcp2_is_write_more(nwrite)) {
                if (consumed > 0) {
                    offset += static_cast<size_t>(consumed);
                }
                quic_client_log.trace("client writev_stream: write_more sid={} consumed={} offset={}", sid, consumed, offset);
                co_await flush_pending_packets_actor(st);
                continue;
            }
            if (ngtcp2_is_draining(nwrite)) {
                quic_client_log.info("client writev_stream: connection draining sid={}", sid);
                st->stop_transport();
                co_return;
            }
            quic_client_log.warn("client writev_stream failed: sid={} nwrite={} msg={}", sid, nwrite, ngtcp2_error_message((int)nwrite));
            st->fail(classify_ngtcp2_error(nwrite), ngtcp2_error_message((int)nwrite));
            co_return;
        }
        if (nwrite == 0) {
            quic_client_log.trace("client writev_stream produced 0 bytes, flushing sid={}", sid);
            co_await flush_pending_packets_actor(st);
            continue;
        }

        if (consumed > 0) {
            offset += static_cast<size_t>(consumed);
        }
        if (!remaining && send_fin) {
            send_fin = false;
        }
        quic_client_log.trace(
          "client writev_stream sent packet: sid={} packet_bytes={} consumed={} offset={} total={} fin_pending={}",
          sid,
          nwrite,
          consumed,
          offset,
          msg.payload.size(),
          send_fin);
        co_await send_datagram(st->channel, st->remote_address, outbuf.data(), static_cast<size_t>(nwrite));

        if (offset >= msg.payload.size() && !send_fin) {
            break;
        }
    }

    co_await flush_pending_packets_actor(st);
    st->request_timer_rearm();
    quic_client_log.debug("client send_stream_message done: sid={} total_bytes={} fin={}", sid, msg.payload.size(), msg.fin);
}

future<> open_stream_actor(lw_shared_ptr<client_state> st, internal::transport_command cmd) {
    if (!st->conn || !cmd.open_result) {
        co_return;
    }

    int64_t sid = invalid_stream_id;
    int rv = cmd.type == stream_type::bidirectional
      ? ngtcp2_conn_open_bidi_stream(st->conn, &sid, nullptr)
      : ngtcp2_conn_open_uni_stream(st->conn, &sid, nullptr);

    if (rv == 0) {
        st->announced_streams.emplace(sid);
        st->runtime->complete_open_stream(cmd.open_result, sid);
        co_await flush_pending_packets_actor(st);
        st->request_timer_rearm();
        co_return;
    }

    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
        st->runtime->fail_open_stream(cmd.open_result, quic_error::unsupported, "stream id blocked");
        co_await flush_pending_packets_actor(st);
        co_return;
    }

    st->runtime->fail_open_stream(cmd.open_result, classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
    st->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
}

future<> reset_stream_actor(lw_shared_ptr<client_state> st, stream_id sid, application_error_code app_error_code) {
    if (!st->conn) {
        co_return;
    }
    int rv = ngtcp2_conn_shutdown_stream(st->conn, 0, sid, app_error_code);
    if (rv < 0) {
        st->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        co_return;
    }
    co_await flush_pending_packets_actor(st);
    st->request_timer_rearm();
}

future<> stop_sending_actor(lw_shared_ptr<client_state> st, stream_id sid, application_error_code app_error_code) {
    if (!st->conn) {
        co_return;
    }
    int rv = ngtcp2_conn_shutdown_stream_read(st->conn, 0, sid, app_error_code);
    if (rv < 0) {
        st->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        co_return;
    }
    co_await flush_pending_packets_actor(st);
    st->request_timer_rearm();
}

future<> recv_datagram_actor(lw_shared_ptr<client_state> st, const socket_address& src, temporary_buffer<char> pkt) {
    if (!st->active() || !st->conn) {
        co_return;
    }
    quic_client_log.trace("client recv_datagram_actor: src={} bytes={}", src, pkt.size());

    sockaddr_storage remote_ss{};
    socklen_t remote_ss_len = 0;
    to_sockaddr_storage_v6(src, remote_ss, remote_ss_len);

    ngtcp2_path path{};
    init_ngtcp2_addr(&path.local, reinterpret_cast<sockaddr*>(&st->local_ss), st->local_ss_len);
    init_ngtcp2_addr(&path.remote, reinterpret_cast<sockaddr*>(&remote_ss), remote_ss_len);
    ngtcp2_pkt_info pkt_info{};
    int rv = ngtcp2_conn_read_pkt(
      st->conn, &path, &pkt_info, reinterpret_cast<const uint8_t*>(pkt.get()), pkt.size(), now_ns());
    if (rv < 0) {
        if (ngtcp2_is_draining(rv)) {
            quic_client_log.info("client recv_datagram_actor: connection draining");
            st->stop_transport();
            co_return;
        }
        quic_client_log.warn("client recv_datagram_actor failed: rv={} msg={}", rv, ngtcp2_error_message(rv));
        st->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
        co_return;
    }

    sync_current_path(*st);
    co_await flush_pending_packets_actor(st);
    st->request_timer_rearm();
}

future<> handle_timer_actor(lw_shared_ptr<client_state> st) {
    if (!st->active() || !st->conn) {
        co_return;
    }

    auto now_local = now_ns();
    if (ngtcp2_conn_get_expiry(st->conn) <= now_local) {
        int rv = ngtcp2_conn_handle_expiry(st->conn, now_local);
        if (rv < 0) {
            if (ngtcp2_is_idle_close(rv) || ngtcp2_is_draining(rv)) {
                st->stop_transport();
                co_return;
            }
            st->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
            co_return;
        }
    }
    co_await flush_pending_packets_actor(st);
}

future<> send_connection_close_actor(lw_shared_ptr<client_state> st) {
    if (!st->conn || !st->channel_ready || st->channel.is_closed()) {
        co_return;
    }

    ngtcp2_path path{};
    st->fill_path(path);
    ngtcp2_pkt_info pkt_info{};
    std::vector<uint8_t> outbuf(st->tx_payload_limit);

    ngtcp2_ccerr ccerr{};
    ngtcp2_ccerr_default(&ccerr);
    ngtcp2_ccerr_set_application_error(&ccerr, 0, nullptr, 0);

    ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
      st->conn, &path, &pkt_info, outbuf.data(), outbuf.size(), &ccerr, now_ns());
    if (nwrite == 0) {
        quic_client_log.debug("client stop: no CONNECTION_CLOSE packet produced");
        co_return;
    }
    if (nwrite < 0) {
        quic_client_log.warn(
          "client stop: failed to write CONNECTION_CLOSE nwrite={} msg={}",
          nwrite,
          ngtcp2_error_message((int)nwrite));
        co_return;
    }

    quic_client_log.info("client sent CONNECTION_CLOSE packet bytes={}", nwrite);
    co_await send_datagram(st->channel, st->remote_address, outbuf.data(), static_cast<size_t>(nwrite));
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

future<> command_loop(lw_shared_ptr<client_state> st) {
    while (st->active()) {
        internal::transport_command cmd;
        try {
            cmd = co_await st->runtime->pop_command();
        } catch (const quic_exception& e) {
            if (e.code() == quic_error::closed) {
                quic_client_log.debug("client command_loop exiting on closed runtime");
                st->request_stop();
                co_return;
            }
            quic_client_log.warn("client command_loop pop_command error: code={} detail='{}'", to_string(e.code()), e.what());
            st->fail(e.code(), e.what());
            co_return;
        } catch (...) {
            quic_client_log.error("client command_loop unexpected pop_command failure");
            st->fail(quic_error::internal, "pop_command failed");
            co_return;
        }

        try {
            auto out = std::make_unique<internal::transport_command>(std::move(cmd));
            co_await st->op_queue.push_eventually(std::move(out));
            st->wake_actor();
        } catch (...) {
            if (st->stopping || !st->runtime || !st->runtime->is_open()) {
                co_return;
            }
            st->fail(quic_error::io, "command queue push failed");
            co_return;
        }
    }
}

future<> timer_loop(lw_shared_ptr<client_state> st) {
    constexpr auto max_timer_sleep = std::chrono::hours(24);
    while (st->active()) {
        if (!st->conn) {
            co_return;
        }

        auto expiry = ngtcp2_conn_get_expiry(st->conn);
        auto now = now_ns();
        if (expiry <= now) {
            st->signal_tick();
            try {
                co_await st->timer_cv.wait([st] {
                    return !st->active() || st->stop_requested || st->timer_rearm_requested || !st->tick_pending;
                });
            } catch (...) {
            }
            st->timer_rearm_requested = false;
            continue;
        }

        auto wait_ns = expiry - now;
        auto max_wait_ns = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::nanoseconds>(max_timer_sleep).count());
        auto sleep_ns = wait_ns > max_wait_ns ? max_wait_ns : wait_ns;
        st->timer_rearm_requested = false;

        try {
            co_await st->timer_cv.wait(std::chrono::nanoseconds(sleep_ns), [st] {
                return !st->active() || st->stop_requested || st->timer_rearm_requested;
            });
            st->timer_rearm_requested = false;
        } catch (const condition_variable_timed_out&) {
            if (!st->active()) {
                co_return;
            }
            st->signal_tick();
        } catch (...) {
            if (!st->active()) {
                co_return;
            }
        }
    }
}

future<> actor_loop(lw_shared_ptr<client_state> st) {
    while (st->active()) {
        if (!st->has_pending_actor_work()) {
            co_await st->wait_for_actor_wakeup();
            if (!st->active()) {
                co_return;
            }
        }

        if (st->stop_requested) {
            co_await send_connection_close_actor(st);
            st->stop_transport();
            co_return;
        }

        while (st->active() && !st->rx_queue.empty()) {
            auto evt = st->rx_queue.pop();
            if (!evt) {
                continue;
            }
            co_await recv_datagram_actor(st, evt->src, std::move(evt->packet));
        }

        while (st->active() && !st->op_queue.empty()) {
            auto out = st->op_queue.pop();
            if (!out) {
                continue;
            }
            if (!st->handshake_done) {
                st->pre_handshake_ops.push_back(std::move(*out));
                continue;
            }
            switch (out->op) {
            case internal::transport_command::kind::send:
                co_await send_stream_message_actor(st, std::move(out->msg));
                break;
            case internal::transport_command::kind::open_stream:
                co_await open_stream_actor(st, std::move(*out));
                break;
            case internal::transport_command::kind::reset_stream:
                co_await reset_stream_actor(st, out->msg.stream, out->app_error_code);
                break;
            case internal::transport_command::kind::stop_sending:
                co_await stop_sending_actor(st, out->msg.stream, out->app_error_code);
                break;
            case internal::transport_command::kind::close_connection:
                st->request_stop();
                break;
            }
        }

        while (st->active() && st->handshake_done && !st->pre_handshake_ops.empty()) {
            auto cmd = std::move(st->pre_handshake_ops.front());
            st->pre_handshake_ops.pop_front();
            switch (cmd.op) {
            case internal::transport_command::kind::send:
                co_await send_stream_message_actor(st, std::move(cmd.msg));
                break;
            case internal::transport_command::kind::open_stream:
                co_await open_stream_actor(st, std::move(cmd));
                break;
            case internal::transport_command::kind::reset_stream:
                co_await reset_stream_actor(st, cmd.msg.stream, cmd.app_error_code);
                break;
            case internal::transport_command::kind::stop_sending:
                co_await stop_sending_actor(st, cmd.msg.stream, cmd.app_error_code);
                break;
            case internal::transport_command::kind::close_connection:
                st->request_stop();
                break;
            }
        }

        if (st->active() && st->tick_pending) {
            st->tick_pending = false;
            st->timer_cv.signal();
            co_await handle_timer_actor(st);
        }
    }
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
    (void)with_gate(st->task_gate, [st] { return command_loop(st); })
      .handle_exception([st](std::exception_ptr) {
          if (st->active()) {
              st->fail(quic_error::io, "command loop failed");
          }
      })
      .or_terminate();
    (void)with_gate(st->task_gate, [st] { return timer_loop(st); })
      .handle_exception([st](std::exception_ptr) {
          if (st->active()) {
              st->fail(quic_error::io, "timer loop failed");
          }
      })
      .or_terminate();
}

class quic_client_impl {
public:
    future<internal::session_runtime_ptr> connect(quic_client_config config) {
        if (_state) {
            throw_quic_error(quic_error::invalid_state, "client is already connected");
        }
        ensure_gnutls_global();
        quic_client_log.info(
          "client connect start: remote={} local={} server_name='{}' alpn_count={}",
          config.remote_address,
          config.local_address.value_or(socket_address(ipv6_addr{0})),
          config.server_name,
          config.alpns.size());

        auto st = make_lw_shared<client_state>();
        st->cfg = std::move(config);
        st->runtime = internal::make_session_runtime(st->cfg.session_options);
        st->remote_address = st->cfg.remote_address;
        st->handshake_promise.emplace();

        std::exception_ptr init_error;
        try {
            auto local = st->cfg.local_address.value_or(socket_address(ipv6_addr{0}));
            st->channel = engine().net().make_bound_datagram_channel(local);
            st->channel_ready = true;
            st->local_address = st->channel.local_address();

            to_sockaddr_storage_v6(st->local_address, st->local_ss, st->local_ss_len);
            to_sockaddr_storage_v6(st->remote_address, st->remote_ss, st->remote_ss_len);

            init_tls(*st);
            init_client_connection(*st);

            co_await flush_pending_packets_actor(st);

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

        co_return st->runtime;
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
    auto runtime = co_await _impl->connect(std::move(config));
    co_return connection(std::move(runtime));
}

future<> quic_client::stop() {
    quic_client_log.debug("quic_client::stop");
    co_await _impl->stop();
}

} // namespace seastar::quic::experimental
