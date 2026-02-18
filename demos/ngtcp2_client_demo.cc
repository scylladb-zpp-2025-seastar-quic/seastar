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

#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/future.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/when_all.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/iostream.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/net/api.hh>

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <array>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <fmt/core.h>
#include <fmt/ostream.h>

#include "../../bazinga/apps/lib/stop_signal.hh"
#include <seastar/quic/quic.hh>
#include <seastar/quic/quic_client.hh>
#include <seastar/quic/quic_error.hh>

static constexpr const char* SERVER_HOST = "localhost";
static constexpr const char* SERVER_IP   = "::1";
static constexpr uint16_t    SERVER_PORT = 4444;
static constexpr size_t      MAX_UDP_OUT = 65536;

static seastar::logger qlog("quic-client");

// Assume that error other than listed is fatal.
static bool is_fatal_error(int code) {
    return code < 0 && !seastar::quic::experimental::is_draining(code) 
                    && !seastar::quic::experimental::should_write_more(code) 
                    && !seastar::quic::experimental::is_idle_close(code);
}

static seastar::temporary_buffer<char> packet_to_tb(seastar::net::packet& pkt) {
    const size_t n = pkt.len();
    seastar::temporary_buffer<char> tb(n);
    char* dst = tb.get_write();
    size_t off = 0;
    for (auto& frag : pkt.fragments()) {
        std::memcpy(dst + off, frag.base, frag.size);
        off += frag.size;
    }
    return tb;
}

class SeastarDgramSocket {
public:
    SeastarDgramSocket(seastar::net::datagram_channel ch,
                       seastar::socket_address local,
                       seastar::socket_address remote)
        : ch_(std::move(ch)), local_(local), remote_(remote) {}

    seastar::future<> send_to(const seastar::socket_address& to, seastar::temporary_buffer<char> tb) {
        return ch_.send(to, std::move(tb));
    }
    seastar::future<seastar::net::datagram> recv_one() { return ch_.receive(); }

    void shutdown() { ch_.close(); }

    const seastar::socket_address& local_address()  const { return local_; }
    const seastar::socket_address& remote_address() const { return remote_; }

private:
    seastar::net::datagram_channel ch_;
    seastar::socket_address local_;
    seastar::socket_address remote_;
};

struct conn_data : public seastar::quic::experimental::Connection {
    bool closing = false;
    bool handshake_done = false;

    int64_t stream_id = -1;
    bool stream_opened = false;

    seastar::condition_variable timer_cv;

    conn_data() = default;

    // Gives signal to start iteration of connection_timer_loop.
    void reschedule() {
        timer_cv.signal();
    }

    ~conn_data() {
        timer_cv.broken();
    }
};

using conn_data_ptr = seastar::lw_shared_ptr<conn_data>;
using sock_ptr   = seastar::lw_shared_ptr<SeastarDgramSocket>;

// Callbacks.

static int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void*) {
    cid->datalen = cidlen;
    seastar::quic::experimental::rand_bytes(cid->data, cidlen);
    seastar::quic::experimental::rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t *data, void*) {
    seastar::quic::experimental::rand_bytes(data, 8);
    return 0;
}

static int handshake_completed_cb(ngtcp2_conn*, void* user_data) {
    auto* c = static_cast<conn_data*>(user_data);
    c->handshake_done = true;
    qlog.info("Handshake completed. Write text and press ENTER:");
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn*, uint32_t, int64_t,
                               uint64_t, const uint8_t* data, size_t datalen,
                               void*, void*) {
    fmt::print("[Server]: {:.{}}", (const char*)data, datalen);
    return 0;
}

static void init_quic(conn_data& c) {
    seastar::quic::experimental::QuicConfig conf;
    conf.withCallbacks([](auto& callbacks) {
        callbacks.get_new_connection_id = get_new_connection_id_cb;
        callbacks.get_path_challenge_data = get_path_challenge_data_cb;
        callbacks.recv_stream_data = recv_stream_data_cb;
        callbacks.handshake_completed = handshake_completed_cb;
    });

    c.generate_random_cids(8);
    c.init_client(conf, &c);
}

static seastar::future<> send_pending_pkts(conn_data_ptr c, sock_ptr sock) {
    if (!c || !sock || !c->conn() || c->closing) co_return;

    std::vector<uint8_t> outbuf(c->max_tx_udp_payload_size());
    
    while (true) {
        ssize_t nwrite = c->write_pending_packet(outbuf.data(), outbuf.size());

        if (nwrite == 0) co_return;
        
        if (nwrite < 0) {
            if (is_fatal_error(nwrite)) {
                qlog.warn("write_pkt: {}", seastar::quic::experimental::error_to_string(nwrite));
            }
            co_return;
        }

        auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
        std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
        co_await sock->send_to(sock->remote_address(), std::move(tb));
    }
}

static void try_open_stream(conn_data& c) {
    if (c.stream_opened) return;
    int rv = c.open_bidi_stream(c.stream_id);
    if (rv == 0) {
        c.stream_opened = true;
        qlog.info("Opened stream id={}", c.stream_id);
        return;
    }
    if (seastar::quic::experimental::should_write_more(rv)) {
        return;
    }
    qlog.error("open_bidi_stream failed: {}", seastar::quic::experimental::error_to_string(rv));
}

static seastar::future<> send_message(conn_data_ptr c, sock_ptr sock, std::string msg) {
    if (!c->handshake_done || !c->conn() || c->closing) co_return;

    try_open_stream(*c);
    if (!c->stream_opened) {
        qlog.warn("Stream not opened, cannot send message");
        co_return;
    }

    std::vector<uint8_t> outbuf(c->max_tx_udp_payload_size());
    
    size_t total_sent = 0;

    while (total_sent < msg.size() && !c->closing) {
        
        ssize_t consumed = 0;
        
        const uint8_t* current_ptr = reinterpret_cast<const uint8_t*>(msg.data()) + total_sent;
        size_t current_len = msg.size() - total_sent;

        ssize_t nwrite = c->write_stream_packet(
            c->stream_id,
            current_ptr, current_len,
            consumed,
            outbuf.data(), outbuf.size()
        );

        if (nwrite < 0) {
            if (!seastar::quic::experimental::should_write_more(nwrite)) {
                qlog.error("send_message error: {}", seastar::quic::experimental::error_to_string(nwrite));
                c->closing = true;
            }
            break;
        }

        if (nwrite == 0) {
            break; 
        }

        auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
        std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
        co_await sock->send_to(sock->remote_address(), std::move(tb));

        total_sent += consumed;
    }
    
    co_await send_pending_pkts(c, sock);
}


static seastar::future<> send_connection_close(conn_data_ptr c, sock_ptr sock) {
    if (!c || !sock || !c->conn()) co_return;

    std::vector<uint8_t> outbuf(c->max_tx_udp_payload_size());

    ssize_t nwrite = c->write_connection_close(outbuf.data(), outbuf.size());

    if (nwrite > 0) {
        auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
        std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
        co_await sock->send_to(sock->remote_address(), std::move(tb));
        qlog.info("Sending CONNECTION_CLOSE.");
    }
}

static seastar::future<> net_loop(conn_data_ptr c, sock_ptr sock) {
    while (!c->closing) {
        try {
            auto d = co_await sock->recv_one();
            auto& pkt = d.get_data();
            auto tb = packet_to_tb(pkt);

            int rv = c->read_packet((const uint8_t*)tb.get(), tb.size());

            if (rv < 0) {
                if (seastar::quic::experimental::is_draining(rv)) {
                    qlog.info("Server closed connection (draining)");
                    c->closing = true;
                    c->reschedule();
                    sock->shutdown();
                    break;
                }
                qlog.error("read_pkt error: {}", seastar::quic::experimental::error_to_string(rv));
                continue;
            }

            c->reschedule();

            co_await send_pending_pkts(c, sock);
        } catch (...) {
            if (c->closing) break;
        }
    }
}

static seastar::future<> input_loop(conn_data_ptr c, sock_ptr sock) {
    int flags = fcntl(0, F_GETFL, 0);
    fcntl(0, F_SETFL, flags | O_NONBLOCK);

    char buf[1024];

    while (!c->closing) {
        ssize_t n = read(0, buf, sizeof(buf));
        if (n > 0) {
            std::string msg;
            for (ssize_t i = 0; i < n; ++i) {
                if ((buf[i] >= 32 && buf[i] <= 126) || buf[i] == '\n') {
                    msg.push_back(buf[i]);
                }
            }

            co_await send_message(c, sock, msg);
            
            c->reschedule();
        } 
        else if (n == 0) {
            co_await send_connection_close(c, sock);
            c->closing = true;
            c->reschedule();
            sock->shutdown();
            break;
        } 
        else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                co_await seastar::sleep(std::chrono::milliseconds(50));
            } else {
                qlog.error("stdin error: {}", strerror(errno));
                c->closing = true;
                c->reschedule();
                sock->shutdown();
                break;
            }
        }
    }
}

static seastar::future<> connection_timer_loop(conn_data_ptr c, sock_ptr sock) {
    while (!c->closing) {
        auto now = seastar::quic::experimental::now_ns();
        auto expiry = c->get_expiry();

        try {
            if (expiry == UINT64_MAX) {
                co_await c->timer_cv.wait();
            } 
            else if (expiry > now) {
                co_await c->timer_cv.wait(std::chrono::nanoseconds(expiry - now));
            }
        }
        catch (const seastar::condition_variable_timed_out&) {}
        catch (seastar::broken_condition_variable&) {
            break;
        }
        
        if (c->closing) break;

        now = seastar::quic::experimental::now_ns();
        if (c->get_expiry() <= now) {
            int rv = c->handle_expiry();
            if (seastar::quic::experimental::is_idle_close(rv)) {
                qlog.info("Connection idle timeout");
                c->closing = true;
                c->reschedule();
                sock->shutdown();
                break;
            }
        }

        co_await send_pending_pkts(c, sock);
    }
}

int main(int argc, char** argv) {
    std::srand((unsigned)time(nullptr));

    if (gnutls_global_init() < 0) {
        std::cerr << "gnutls_global_init failed\n";
        return 1;
    }

    seastar::app_template app;
    int rc = app.run(argc, argv, []() -> seastar::future<int> {
        try {
            seastar_apps_lib::stop_signal stop_signal;
            auto crypto = seastar::make_lw_shared<seastar::quic::experimental::client::client_crypto_config>(
                                                std::vector<std::string>{"hq-interop", "h3"});

            auto c = seastar::make_lw_shared<conn_data>();
            c->set_tls(crypto->make_session(SERVER_HOST, c->conn_ref_ptr()));

            seastar::socket_address local = seastar::socket_address(seastar::ipv6_addr{0});

            sockaddr_in6 r{};
            r.sin6_family = AF_INET6;
            r.sin6_port   = htons(SERVER_PORT);
            if (inet_pton(AF_INET6, SERVER_IP, &r.sin6_addr) != 1) {
                throw std::runtime_error("inet_pton failed for SERVER_IP");
            }
            seastar::socket_address remote = seastar::socket_address(r);

            auto ch = seastar::engine().net().make_bound_datagram_channel(local);
            auto real_local = ch.local_address();
            auto sock = seastar::make_lw_shared<SeastarDgramSocket>(std::move(ch), real_local, remote);

            c->set_local_addr(sock->local_address());
            c->set_remote_addr(sock->remote_address());
            
            init_quic(*c);

            qlog.info("Sending Initial");
            co_await send_pending_pkts(c, sock);
            
            auto net_fut = net_loop(c, sock);
            auto in_fut  = input_loop(c, sock);
            auto tim_fut = connection_timer_loop(c, sock);

            // Waiting for ctrl+c signal.
            auto stop_handler = stop_signal.wait().then([c, sock]() {
                if (!c->closing) {
                    qlog.info("SIGINT received");
                    c->closing = true;
                    sock->shutdown();
                    c->reschedule();
                }
            }).handle_exception([](std::exception_ptr) {});

            co_await seastar::when_all_succeed(std::move(net_fut), std::move(in_fut), std::move(tim_fut));

            if (!c->closing) {
                c->closing = true;
            }

            sock->shutdown();
            c->reschedule();

            co_return 0;

        } catch (const std::exception& e) {
            qlog.error("fatal: {}", e.what());
            co_return 1;
        }
    });

    gnutls_global_deinit();
    return rc;
}
