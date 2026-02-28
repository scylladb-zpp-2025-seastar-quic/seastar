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
#include <utility>
#include <vector>

#include <gnutls/crypto.h>
#include <gnutls/gnutls.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <seastar/core/coroutine.hh>
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
    queue<std::unique_ptr<quic_message>> tx_queue{1024};
    std::deque<quic_message> pre_handshake_tx;
    std::optional<promise<>> actor_waiter;
    bool tick_pending = false;
    bool queues_aborted = false;
    bool stop_requested = false;

    bool stopping = false;
    bool handshake_done = false;
    bool stream_opened = false;
    stream_id stream_sid = invalid_stream_id;
    size_t tx_payload_limit = default_udp_payload_size;

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
        return stop_requested || !rx_queue.empty() || !tx_queue.empty() || tick_pending || (handshake_done && !pre_handshake_tx.empty());
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

    void abort_event_queues(const char* why) {
        if (queues_aborted) {
            return;
        }
        queues_aborted = true;
        auto ex = std::make_exception_ptr(std::runtime_error(why));
        rx_queue.abort(ex);
        tx_queue.abort(std::move(ex));
    }

    void request_stop() {
        if (stopping || stop_requested) {
            return;
        }
        stop_requested = true;
        wake_actor();
    }

    void stop_transport() {
        quic_client_log.info(
          "client transport stop: local={} remote={} handshake_done={} stream_opened={} stream_sid={} channel_ready={}",
          local_address,
          remote_address,
          handshake_done,
          stream_opened,
          stream_sid,
          channel_ready);
        stopping = true;
        abort_event_queues("client transport stopped");
        if (runtime) {
            runtime->mark_transport_closed();
        }
        wake_actor();
        if (channel_ready && !channel.is_closed()) {
            channel.shutdown_input();
            channel.shutdown_output();
        }
    }

    void fail(quic_error err, const sstring& detail) {
        quic_client_log.error(
          "client transport failure: error={} detail='{}' local={} remote={} handshake_done={} stream_opened={} stream_sid={}",
          to_string(err),
          detail,
          local_address,
          remote_address,
          handshake_done,
          stream_opened,
          stream_sid);
        stopping = true;
        abort_event_queues("client transport failed");
        if (runtime) {
            runtime->mark_error(err, detail);
        }
        wake_actor();
        if (channel_ready && !channel.is_closed()) {
            channel.shutdown_input();
            channel.shutdown_output();
        }
    }
};

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

int handshake_completed_cb(ngtcp2_conn*, void* user_data) {
    auto* st = static_cast<client_state*>(user_data);
    st->handshake_done = true;
    quic_client_log.info("client handshake completed");

    if (!st->stream_opened && st->conn) {
        int64_t sid = invalid_stream_id;
        int rv = ngtcp2_conn_open_bidi_stream(st->conn, &sid, nullptr);
        if (rv == 0) {
            st->stream_opened = true;
            st->stream_sid = sid;
            st->runtime->mark_ready(sid);
            quic_client_log.info("client opened default bidi stream sid={}", sid);
        } else {
            quic_client_log.warn("client failed to open bidi stream after handshake: rv={}", rv);
        }
    }

    st->wake_actor();
    return 0;
}

int recv_stream_data_cb(ngtcp2_conn*, uint32_t, int64_t sid, uint64_t, const uint8_t* data, size_t datalen, void* user_data, void*) {
    auto* st = static_cast<client_state*>(user_data);
    if (!st->runtime || !st->runtime->is_open()) {
        quic_client_log.trace("client drop recv_stream_data: sid={} bytes={} runtime_open={}", sid, datalen, st->runtime && st->runtime->is_open());
        return 0;
    }
    quic_client_log.trace("client recv_stream_data: sid={} bytes={}", sid, datalen);
    temporary_buffer<char> tb(datalen);
    if (datalen) {
        std::memcpy(tb.get_write(), data, datalen);
    }
    st->runtime->push_incoming(quic_message(sid, std::move(tb), false));
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
    callbacks.handshake_completed = handshake_completed_cb;
    callbacks.recv_stream_data = recv_stream_data_cb;

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
      "client QUIC connection initialized: local={} remote={} tx_payload_limit={} initial_stream_id={}",
      st.local_address,
      st.remote_address,
      st.tx_payload_limit,
      st.cfg.session_options.initial_stream_id);
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
    if (!st->conn) {
        co_return;
    }
    quic_client_log.debug(
      "client send_stream_message start: requested_sid={} bytes={} fin={} stream_opened={} default_sid={}",
      msg.stream,
      msg.payload.size(),
      msg.fin,
      st->stream_opened,
      st->stream_sid);

    if (!st->stream_opened) {
        int64_t sid = invalid_stream_id;
        int rv = ngtcp2_conn_open_bidi_stream(st->conn, &sid, nullptr);
        if (rv == 0) {
            st->stream_opened = true;
            st->stream_sid = sid;
            st->runtime->mark_ready(sid);
            quic_client_log.info("client lazily opened bidi stream sid={}", sid);
        } else if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) {
            quic_client_log.debug("client stream open blocked, flushing pending packets");
            co_await flush_pending_packets_actor(st);
            co_return;
        } else {
            quic_client_log.warn("client failed opening bidi stream: rv={} msg={}", rv, ngtcp2_error_message(rv));
            st->fail(classify_ngtcp2_error(rv), ngtcp2_error_message(rv));
            co_return;
        }
    }

    int64_t sid = msg.stream == invalid_stream_id ? st->stream_sid : msg.stream;
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
    quic_client_log.debug("client send_stream_message done: sid={} total_bytes={} fin={}", sid, msg.payload.size(), msg.fin);
}

future<> recv_datagram_actor(lw_shared_ptr<client_state> st, temporary_buffer<char> pkt) {
    if (!st->active() || !st->conn) {
        co_return;
    }
    quic_client_log.trace("client recv_datagram_actor: bytes={}", pkt.size());

    ngtcp2_path path{};
    st->fill_path(path);
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

    co_await flush_pending_packets_actor(st);
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

future<> tx_loop(lw_shared_ptr<client_state> st) {
    while (st->active()) {
        quic_message msg;
        try {
            msg = co_await st->runtime->pop_outgoing();
        } catch (const quic_exception& e) {
            if (e.code() == quic_error::closed) {
                quic_client_log.debug("client tx_loop exiting on closed runtime");
                st->request_stop();
                co_return;
            }
            quic_client_log.warn("client tx_loop pop_outgoing error: code={} detail='{}'", to_string(e.code()), e.what());
            st->fail(e.code(), e.what());
            co_return;
        } catch (...) {
            quic_client_log.error("client tx_loop pop_outgoing unexpected failure");
            st->fail(quic_error::internal, "pop_outgoing failed");
            co_return;
        }
        quic_client_log.trace("client tx_loop popped message: sid={} bytes={} fin={}", msg.stream, msg.payload.size(), msg.fin);

        try {
            auto out = std::make_unique<quic_message>(std::move(msg));
            co_await st->tx_queue.push_eventually(std::move(out));
            st->wake_actor();
        } catch (...) {
            if (st->stopping || !st->runtime || !st->runtime->is_open()) {
                co_return;
            }
            st->fail(quic_error::io, "tx queue push failed");
            co_return;
        }
    }
}

future<> timer_loop(lw_shared_ptr<client_state> st) {
    while (st->active()) {
        co_await sleep(std::chrono::milliseconds(200));
        if (!st->active()) {
            co_return;
        }
        st->signal_tick();
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
            to_sockaddr_storage_v6(evt->src, st->remote_ss, st->remote_ss_len);
            co_await recv_datagram_actor(st, std::move(evt->packet));
        }

        while (st->active() && !st->tx_queue.empty()) {
            auto out = st->tx_queue.pop();
            if (!out) {
                continue;
            }
            if (!st->handshake_done) {
                st->pre_handshake_tx.push_back(std::move(*out));
                continue;
            }
            co_await send_stream_message_actor(st, std::move(*out));
        }

        while (st->active() && st->handshake_done && !st->pre_handshake_tx.empty()) {
            auto msg = std::move(st->pre_handshake_tx.front());
            st->pre_handshake_tx.pop_front();
            co_await send_stream_message_actor(st, std::move(msg));
        }

        if (st->active() && st->tick_pending) {
            st->tick_pending = false;
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
    (void)with_gate(st->task_gate, [st] { return tx_loop(st); })
      .handle_exception([st](std::exception_ptr) {
          if (st->active()) {
              st->fail(quic_error::io, "transmit loop failed");
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
            _state = st;
            quic_client_log.info(
              "client connect initialized: local={} remote={} tx_payload_limit={} handshake_done={}",
              st->local_address,
              st->remote_address,
              st->tx_payload_limit,
              st->handshake_done);
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
