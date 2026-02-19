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
#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/when_all.hh>
#include <seastar/net/api.hh>

#include <arpa/inet.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <fmt/core.h>
#include <fmt/ostream.h>

#include "../../bazinga/apps/lib/stop_signal.hh"
#include <seastar/quic/quic.hh>
#include <seastar/quic/quic_server.hh>
#include <seastar/quic/quic_error.hh>

static constexpr const char *LISTEN_IP = "::1";
static constexpr uint16_t LISTEN_PORT = 4444;

static constexpr size_t SERVER_CID_LEN = 8;
static constexpr const char *CERT_FILE = "server.crt";
static constexpr const char *KEY_FILE = "server.key";

static seastar::logger qlog("quic-server");


static std::string g_cert_path = CERT_FILE;
static std::string g_key_path = KEY_FILE;

static bool parse_kv_arg(const char *arg, const char *key, std::string &out) {
    const size_t klen = std::strlen(key);
    if (std::strncmp(arg, key, klen) != 0) return false;
    if (arg[klen] != '=') return false;
    out = std::string(arg + klen + 1);
    return true;
}

static void parse_tls_args(int &argc, char **argv) {
    std::vector<char *> keep;
    keep.reserve(static_cast<size_t>(argc));
    keep.push_back(argv[0]);

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        if (std::strcmp(a, "--crt") == 0 && i + 1 < argc) {
            g_cert_path = argv[++i];
            continue;
        }
        if (std::strcmp(a, "--key") == 0 && i + 1 < argc) {
            g_key_path = argv[++i];
            continue;
        }
        if (parse_kv_arg(a, "--crt", g_cert_path)) continue;
        if (parse_kv_arg(a, "--key", g_key_path)) continue;
        keep.push_back(argv[i]);
    }

    for (size_t i = 0; i < keep.size(); ++i) argv[i] = keep[i];
    argc = static_cast<int>(keep.size());
}

static bool validate_config() {
    if (SERVER_CID_LEN > 20) {
        qlog.error("Invalid SERVER_CID_LEN (max 20): {}", SERVER_CID_LEN);
        return false;
    }
    if (access(g_cert_path.c_str(), R_OK) != 0) {
        qlog.error("Missing cert file: {} ({})", g_cert_path, strerror(errno));
        return false;
    }
    if (access(g_key_path.c_str(), R_OK) != 0) {
        qlog.error("Missing key file: {} ({})", g_key_path, strerror(errno));
        return false;
    }
    return true;
}

static std::string ip_port_key_v6(const seastar::socket_address &sa) {
    auto in6 = sa.as_posix_sockaddr_in6();
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &in6.sin6_addr, buf, sizeof(buf));
    uint16_t port = ntohs(in6.sin6_port);
    return std::string(buf) + ":" + std::to_string(port);
}

enum class QuicLongType : uint8_t {
    Initial = 0,
    ZeroRTT = 1,
    Handshake = 2,
    Retry = 3
};

struct DcidParseResult {
    bool ok = false;
    bool long_header = false;
    QuicLongType long_type = QuicLongType::Initial;
    std::array<uint8_t, 20> dcid{};
    size_t dcid_len = 0;
};

static DcidParseResult parse_dcid_quic_v1(const uint8_t *pkt, size_t len,
                                          size_t short_dcid_len) {
    DcidParseResult r{};
    if (len < 1) return r;
    uint8_t b0 = pkt[0];
    bool long_header = (b0 & 0x80) != 0;
    r.long_header = long_header;
    if (long_header) {
        if (len < 1 + 4 + 1) return r;
        uint8_t type_bits = (b0 >> 4) & 0x03;
        r.long_type = static_cast<QuicLongType>(type_bits);
        size_t off = 1 + 4;
        if (off >= len) return r;
        uint8_t dcid_len = pkt[off++];
        if (dcid_len > r.dcid.size()) return r;
        if (off + dcid_len > len) return r;
        std::memcpy(r.dcid.data(), pkt + off, dcid_len);
        r.dcid_len = dcid_len;
        r.ok = true;
        return r;
    }
    if (len < 1 + short_dcid_len) return r;
    std::memcpy(r.dcid.data(), pkt + 1, short_dcid_len);
    r.dcid_len = short_dcid_len;
    r.ok = true;
    return r;
}

class SeastarDgramSocket {
   public:
    explicit SeastarDgramSocket(seastar::net::datagram_channel ch)
        : ch_(std::move(ch)) {}

    seastar::future<> send_to(const seastar::socket_address &to,
                              seastar::net::packet p) {
        return ch_.send(to, std::move(p));
    }
    seastar::future<seastar::net::datagram> recv_one() { return ch_.receive(); }
    void shutdown() { ch_.close(); }
    seastar::socket_address local_address() const {
        return ch_.local_address();
    }

   private:
    seastar::net::datagram_channel ch_;
};

struct ServerState;

struct conn_data : public seastar::quic::experimental::Connection {
    ServerState *st = nullptr;

    seastar::socket_address peer{};

    bool closing = false;
    seastar::condition_variable timer_cv;

    std::unordered_set<seastar::quic::experimental::quic_cid> mapped_dcids;
    seastar::quic::experimental::quic_cid last_rx_dcid;

    struct Pending {
        int64_t sid;
        std::string data;
    };
    std::vector<Pending> pending_echo;

    ~conn_data() {
        timer_cv.broken();
    }

    // Gives signal to start iteration of connection_timer_loop.
    void reschedule() {
        timer_cv.signal();
    }
};

using conn_data_ptr = seastar::lw_shared_ptr<conn_data>;
using sock_ptr = seastar::lw_shared_ptr<SeastarDgramSocket>;

struct ServerState {
    sock_ptr sock;
    seastar::socket_address listen_addr;
    seastar::quic::experimental::server_crypto_config_ptr crypto;
    bool stopping = false;
    std::unordered_map<seastar::quic::experimental::quic_cid, conn_data_ptr> by_dcid;
    std::vector<conn_data_ptr> conns;
};

static std::string dcid_or_unknown(const conn_data *c) {
    if (!c || c->last_rx_dcid.empty()) return "?";
    return c->last_rx_dcid.to_string();
}

static void map_dcid(ServerState &st, const conn_data_ptr &c, const seastar::quic::experimental::quic_cid& cid) {
    st.by_dcid[cid] = c;
    c->mapped_dcids.insert(cid);
}

static void unmap_all_dcids(ServerState &st, const conn_data_ptr &c) {
    for (const auto &cid : c->mapped_dcids) {
        auto it = st.by_dcid.find(cid);
        if (it != st.by_dcid.end() && it->second == c) {
            st.by_dcid.erase(it);
        }
    }
    c->mapped_dcids.clear();
}

static void unmap_dcid(ServerState &st, const conn_data_ptr &c, const seastar::quic::experimental::quic_cid &cid) {
    auto it = st.by_dcid.find(cid);
    if (it != st.by_dcid.end() && it->second == c) {
        st.by_dcid.erase(it);
    }
    c->mapped_dcids.erase(cid);
}

static void remove_conn(ServerState &st, const conn_data_ptr &c) {
    if (c) {
        qlog.info("Removing connection peer={} dcids={}", ip_port_key_v6(c->peer), c->mapped_dcids.size());
    }
    unmap_all_dcids(st, c);
    auto &v = st.conns;
    v.erase(std::remove(v.begin(), v.end(), c), v.end());
}

static conn_data_ptr find_conn_ptr(ServerState &st, conn_data *raw) {
    for (auto &c : st.conns) {
        if (c.get() == raw) return c;
    }
    return {};
}

// Callbacks.
static int get_new_connection_id_cb(ngtcp2_conn *, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen, void *) {
    cid->datalen = cidlen;
    seastar::quic::experimental::rand_bytes(cid->data, cidlen);
    seastar::quic::experimental::rand_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

static int get_path_challenge_data_cb(ngtcp2_conn *, uint8_t *data, void *) {
    seastar::quic::experimental::rand_bytes(data, 8);
    return 0;
}

static int handshake_completed_cb(ngtcp2_conn *, void *user_data) {
    auto *c = static_cast<conn_data *>(user_data);
    qlog.info("Handshake completed with {}", ip_port_key_v6(c->peer));
    return 0;
}

static int dcid_status_cb(ngtcp2_conn *, ngtcp2_connection_id_status_type type,
                          uint64_t, const ngtcp2_cid *cid, const uint8_t *,
                          void *user_data) {
    auto *c = static_cast<conn_data *>(user_data);
    if (!c || !c->st || !cid) return 0;
    auto cp = find_conn_ptr(*c->st, c);
    if (!cp) return 0;

if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_ACTIVATE) {
        map_dcid(*c->st, cp, seastar::quic::experimental::quic_cid(*cid)); 
        qlog.info("DCID activate peer={} dcid={}", 
                  ip_port_key_v6(c->peer), seastar::quic::experimental::quic_cid(*cid));
    } else if (type == NGTCP2_CONNECTION_ID_STATUS_TYPE_DEACTIVATE) {
        unmap_dcid(*c->st, cp, seastar::quic::experimental::quic_cid(*cid));
        qlog.info("DCID deactivate peer={} dcid={}", 
                  ip_port_key_v6(c->peer), seastar::quic::experimental::quic_cid(*cid));
    }
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *, uint32_t, int64_t sid, uint64_t,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *) {
    auto *c = static_cast<conn_data *>(user_data);
    if (c->closing) return 0;
    std::string s(reinterpret_cast<const char *>(data), datalen);

    fmt::print("[Client {}]: {}", ip_port_key_v6(c->peer), s);
    if (!s.empty() && s.back() != '\n') fmt::print("\n");
    std::cout.flush();

    c->pending_echo.push_back(conn_data::Pending{sid, std::move(s)});
    return 0;
}

static seastar::temporary_buffer<char> packet_to_tb(seastar::net::packet &pkt) {
    const size_t n = pkt.len();
    seastar::temporary_buffer<char> tb(n);
    char *dst = tb.get_write();
    size_t off = 0;
    for (auto &frag : pkt.fragments()) {
        std::memcpy(dst + off, frag.base, frag.size);
        off += frag.size;
    }
    return tb;
}


static seastar::future<> flush_echo_and_packets(const conn_data_ptr &c_base,
                                                const sock_ptr &sock) {
    auto *c = static_cast<conn_data*>(c_base.get());                                                
    if (!c || !sock || !c->conn() || c->closing) co_return;

    std::vector<uint8_t> outbuf(c->max_tx_udp_payload_size());
    bool did_write_something = false;

    try {
        while (!c->closing) {
            ssize_t nwrite = 0;

            if (!c->pending_echo.empty()) {
                auto& item = c->pending_echo.back();
                ssize_t consumed = 0;

                nwrite = c->write_stream_packet(
                    item.sid,
                    reinterpret_cast<const uint8_t*>(item.data.data()), item.data.size(),
                    consumed,
                    outbuf.data(), outbuf.size()
                );

                if (nwrite > 0 && consumed > 0) {
                    if ((size_t)consumed >= item.data.size()) {
                        c->pending_echo.pop_back();
                    } else {
                        item.data.erase(0, consumed);
                    }
                }
            } 
            else {
                nwrite = c->write_pending_packet(outbuf.data(), outbuf.size());
            }

            if (nwrite < 0) {
                if (seastar::quic::experimental::should_write_more(nwrite)) {
                    break; 
                }
                if (seastar::quic::experimental::is_draining(nwrite)) {
                    c->closing = true;
                } else {
                    qlog.error("flush write error: {}", seastar::quic::experimental::error_to_string(nwrite));
                    c->closing = true;
                }
                break;
            }

            if (nwrite == 0) {
                break;
            }

            auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
            std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
            
            co_await sock->send_to(c->peer, std::move(tb));
            
            did_write_something = true;
        }
    } catch (const std::exception &e) {
        c->closing = true;
        qlog.error("flush exception peer={}: {}", ip_port_key_v6(c->peer), e.what());
    }

    if (did_write_something && !c->closing) {
        c->reschedule();
    }
}

static seastar::future<> send_connection_close(const conn_data_ptr &c,
                                               const sock_ptr &sock) {
    if (!c || !sock || !c->conn()) co_return;

    std::vector<uint8_t> outbuf(c->max_tx_udp_payload_size());

    ssize_t nwrite = c->write_connection_close(outbuf.data(), outbuf.size());
    if (nwrite <= 0) co_return;

    auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
    std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
    co_await sock->send_to(c->peer, seastar::net::packet(std::move(tb)));
    qlog.info("Sent CONNECTION_CLOSE peer={} dcid={}", 
              ip_port_key_v6(c->peer), dcid_or_unknown(c.get()));
}

// For each connection there is created loop.
static seastar::future<> connection_timer_loop(conn_data_ptr c, sock_ptr sock) {
    qlog.info("Timer loop start peer={}", ip_port_key_v6(c->peer));
    while (!c->closing && !(c->st && c->st->stopping)) {
        co_await flush_echo_and_packets(c, sock);
        if (c->closing) break;

        auto expiry = c->get_expiry();
        auto now = seastar::quic::experimental::now_ns();

        try {
            if (expiry == UINT64_MAX) {
                co_await c->timer_cv.wait();
            } else if (expiry > now) {
                co_await c->timer_cv.wait(
                    std::chrono::nanoseconds(expiry - now));
            }
        } catch (...) {
            if (c->closing) break;
        }

        now = seastar::quic::experimental::now_ns();
        if (c->get_expiry() <= now) {
            int rv = c->handle_expiry();
            if (rv < 0) {
                if (seastar::quic::experimental::is_idle_close(rv)) {
                    qlog.info("Client {} disconnected (idle timeout).", ip_port_key_v6(c->peer));
                } else if (!seastar::quic::experimental::is_draining(rv)) {
                    qlog.error("handle_expiry error peer={} dcid={}: {}", 
                                ip_port_key_v6(c->peer), dcid_or_unknown(c.get()), 
                                seastar::quic::experimental::error_to_string(rv));
                }
                c->closing = true;
            }
        }
    }

    if (c->st) {
        remove_conn(*c->st, c);
    }
}

static seastar::lw_shared_ptr<ServerState> init_server_state(
    seastar::quic::experimental::server_crypto_config_ptr crypto) {
    sockaddr_in6 a{};
    a.sin6_family = AF_INET6;
    a.sin6_port = htons(LISTEN_PORT);
    if (inet_pton(AF_INET6, LISTEN_IP, &a.sin6_addr) != 1) {
        throw std::runtime_error("inet_pton failed for LISTEN_IP");
    }
    auto sock = seastar::make_lw_shared<SeastarDgramSocket>(
        seastar::engine().net().make_bound_datagram_channel(
            seastar::socket_address(a)));
    auto st = seastar::make_lw_shared<ServerState>();
    st->sock = sock;
    st->listen_addr = seastar::socket_address(a);
    st->crypto = std::move(crypto);
    return st;
}

static seastar::future<> handle_datagram(
    const seastar::lw_shared_ptr<ServerState> &st, seastar::net::datagram d) {
    if (st->stopping) co_return;
    auto peer = d.get_src();
    auto &pkt = d.get_data();
    auto tb = packet_to_tb(pkt);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(tb.get());
    size_t n = tb.size();

    auto parsed = parse_dcid_quic_v1(p, n, SERVER_CID_LEN);
    if (!parsed.ok) co_return;

    conn_data_ptr c;
    seastar::quic::experimental::quic_cid key_cid(parsed.dcid.data(), parsed.dcid_len);
    auto it = st->by_dcid.find(key_cid);
    if (it != st->by_dcid.end()) c = it->second;

    if (!c) {
        if (!parsed.long_header || parsed.long_type != QuicLongType::Initial) {
            qlog.debug("Drop non-initial from {} dcid={}", 
                       ip_port_key_v6(peer), key_cid);
            co_return;
        }

        auto nc = seastar::make_lw_shared<conn_data>();
        nc->st = st.get();
        nc->peer = peer;
        nc->set_local_addr(st->listen_addr);
        nc->set_remote_addr(peer);

        seastar::quic::experimental::quic_cid client_odcid;
        try {
            nc->set_tls(st->crypto->make_session(nc->conn_ref_ptr()));
            
            client_odcid = seastar::quic::experimental::quic_cid(nc->parse_initial_packet(p, n));

            nc->generate_scid(SERVER_CID_LEN);

            seastar::quic::experimental::QuicConfig conf;

            conf.withCallbacks([](auto& callbacks){
                callbacks.recv_stream_data = recv_stream_data_cb;
                callbacks.handshake_completed = handshake_completed_cb;
                callbacks.dcid_status = dcid_status_cb;
                callbacks.get_new_connection_id = get_new_connection_id_cb;
                callbacks.get_path_challenge_data = get_path_challenge_data_cb;
            });

            conf.withTransportParams([&](auto& params){
                params.original_dcid_present = 1;
                params.original_dcid = *client_odcid.get();
            });

            nc->init_server(conf, nc.get());

        } catch (const std::exception &e) {
            qlog.error("Init failed peer={}: {}", ip_port_key_v6(peer), e.what());
            co_return;
        } catch (...) {
            qlog.error("Init failed peer={}: unknown error", ip_port_key_v6(peer));
            co_return;
        }

        map_dcid(*st, nc, client_odcid);
        map_dcid(*st, nc, seastar::quic::experimental::quic_cid(*nc->scid_ptr()));
        st->conns.push_back(nc);
        c = nc;

        qlog.info("New connection: peer={}", ip_port_key_v6(peer));
        (void)connection_timer_loop(c, st->sock).or_terminate();
    }

    if (!c || !c->conn() || c->closing) co_return;
    if (c->peer != peer) {
        c->peer = peer;
        c->set_remote_addr(peer);
        qlog.info("Peer address updated for dcid={} peer={}", 
                  key_cid, ip_port_key_v6(peer));
    }
    c->last_rx_dcid = key_cid;

    int rv = c->read_packet(p, n);
    if (rv < 0) {
        if (seastar::quic::experimental::is_draining(rv)) {
            qlog.info("Client {} disconnected.", ip_port_key_v6(c->peer));
        } else {
            qlog.error("Read error peer={} dcid={}: {}", 
                       ip_port_key_v6(c->peer), dcid_or_unknown(c.get()), 
                        seastar::quic::experimental::error_to_string(rv));
        }
        c->closing = true;
    }

    c->reschedule();
}

static seastar::future<> server_loop(seastar::lw_shared_ptr<ServerState> st) {
    while (true) {
        if (st->stopping) co_return;
        try {
            auto d = co_await st->sock->recv_one();
            co_await handle_datagram(st, std::move(d));
        } catch (const std::exception &e) {
            if (st->stopping) co_return;
            qlog.error("server_loop exception: {}", e.what());
        } catch (...) {
            if (st->stopping) co_return;
            qlog.error("server_loop exception: unknown");
        }
    }
}

int main(int argc, char **argv) {
    std::srand((unsigned)time(nullptr));
    
    seastar::quic::experimental::init_gnutls gnutls;

    parse_tls_args(argc, argv);
    if (!validate_config()) return 1;

    seastar::app_template app;
    int rc = app.run(argc, argv, []() -> seastar::future<int> {
        try {
            seastar_apps_lib::stop_signal stop_signal;
            auto crypto = seastar::make_lw_shared<seastar::quic::experimental::server::server_crypto_config>(
                                                g_cert_path, g_key_path, std::vector<std::string>{"hq-interop", "h3"});
            auto st = init_server_state(std::move(crypto));

            qlog.info("QUIC seastar server listening on port {}", LISTEN_PORT);
            auto server_f = server_loop(st);
            co_await stop_signal.wait();

            qlog.info("Stop signal received");
            st->stopping = true;
            qlog.info("Stopping {} connections", st->conns.size());
            auto conns = st->conns;
            std::vector<seastar::future<>> close_futs;
            close_futs.reserve(conns.size());
            for (auto &c : conns) {
                if (!c || c->closing) continue;
                c->closing = true;
                c->reschedule();
                close_futs.push_back(send_connection_close(c, st->sock));
            }
            if (!close_futs.empty()) {
                co_await seastar::when_all_succeed(close_futs.begin(),
                                                   close_futs.end())
                    .discard_result();
            }
            co_await seastar::sleep(std::chrono::milliseconds(200));
            st->sock->shutdown();

            co_await std::move(server_f);
            qlog.info("Shutdown complete");
            co_return 0;
        } catch (const std::exception &e) {
            qlog.error("Fatal: {}", e.what());
            co_return 1;
        }
    });

    return rc;
}
