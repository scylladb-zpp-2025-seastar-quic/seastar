// server_seastar.cc
#include <seastar/core/app-template.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/seastar.hh>
#include <seastar/core/future.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/when_all.hh>
#include <seastar/core/shared_ptr.hh>
#include <seastar/net/api.hh>

#include <gnutls/gnutls.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <arpa/inet.h>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <array>
#include <unordered_map>
#include <vector>

static constexpr const char* LISTEN_IP   = "::1";
static constexpr uint16_t    LISTEN_PORT = 4444;
static constexpr size_t      MAX_UDP_OUT = 65536;

static constexpr const char* CERT_FILE = "server.crt";
static constexpr const char* KEY_FILE  = "server.key";

#define LOG(x) do { std::cerr << x << "\n"; } while (0)

static ngtcp2_tstamp now_ns() {
    using namespace std::chrono;
    return duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count();
}

static void* my_malloc(size_t size, void*) { return std::malloc(size); }
static void  my_free(void* ptr, void*)     { std::free(ptr); }
static void* my_calloc(size_t n, size_t s, void*) { return std::calloc(n, s); }
static void* my_realloc(void* p, size_t s, void*) { return std::realloc(p, s); }
static const ngtcp2_mem g_mem = { nullptr, my_malloc, my_free, my_calloc, my_realloc };

static void init_ngtcp2_addr(ngtcp2_addr* addr, const sockaddr* sa, size_t len) {
    addr->addr    = const_cast<sockaddr*>(sa);
    addr->addrlen = (socklen_t)len;
}

static void sa_to_storage_v6(const seastar::socket_address& sa, sockaddr_storage& out, socklen_t& outlen) {
    std::memset(&out, 0, sizeof(out));
    auto in6 = sa.as_posix_sockaddr_in6();
    outlen = sizeof(sockaddr_in6);
    std::memcpy(&out, &in6, sizeof(sockaddr_in6));
}

static std::string peer_key_v6(const seastar::socket_address& sa) {
    auto in6 = sa.as_posix_sockaddr_in6();
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &in6.sin6_addr, buf, sizeof(buf));
    uint16_t port = ntohs(in6.sin6_port);
    return std::string(buf) + ":" + std::to_string(port);
}

// Seastar datagram wrapper
class SeastarDgramSocket {
public:
    explicit SeastarDgramSocket(seastar::net::datagram_channel ch)
        : ch_(std::move(ch)) {}

    seastar::future<> send_to(const seastar::socket_address& to, seastar::net::packet p) {
        return ch_.send(to, std::move(p));
    }

    seastar::future<seastar::net::datagram> recv_one() {
        return ch_.receive();
    }

    seastar::socket_address local_address() const { return ch_.local_address(); }

private:
    seastar::net::datagram_channel ch_;
};

struct Conn {
    ngtcp2_conn* conn = nullptr;

    gnutls_certificate_credentials_t cred = nullptr;
    gnutls_session_t tls = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};

    seastar::socket_address peer{};
    sockaddr_storage local_ss{};
    socklen_t local_ss_len = 0;
    sockaddr_storage peer_ss{};
    socklen_t peer_ss_len = 0;

    bool closing = false;

    struct Pending {
        int64_t sid;
        std::string data;
    };
    std::vector<Pending> pending_echo;

    ~Conn() {
        if (conn) ngtcp2_conn_del(conn);
        if (tls)  gnutls_deinit(tls);
        if (cred) gnutls_certificate_free_credentials(cred);
    }

    void fill_path(ngtcp2_path& p) {
        init_ngtcp2_addr(&p.local,  (sockaddr*)&local_ss, local_ss_len);
        init_ngtcp2_addr(&p.remote, (sockaddr*)&peer_ss,  peer_ss_len);
    }
};

using conn_ptr = seastar::lw_shared_ptr<Conn>;
using sock_ptr = seastar::lw_shared_ptr<SeastarDgramSocket>;

static ngtcp2_conn* get_conn(ngtcp2_crypto_conn_ref* conn_ref) {
    return (ngtcp2_conn*)conn_ref->user_data;
}

static void rand_cb(uint8_t* dest, size_t destlen, const ngtcp2_rand_ctx*) {
    for (size_t i = 0; i < destlen; ++i) dest[i] = (uint8_t)std::rand();
}

static int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid, uint8_t* token,
                                    size_t cidlen, void*) {
    cid->datalen = cidlen;
    for (size_t i = 0; i < cidlen; ++i) cid->data[i] = (uint8_t)std::rand();
    for (size_t i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i) token[i] = (uint8_t)std::rand();
    return 0;
}

static int get_path_challenge_data_cb(ngtcp2_conn*, uint8_t* data, void*) {
    for (size_t i = 0; i < 8; ++i) data[i] = (uint8_t)std::rand();
    return 0;
}

static int handshake_completed_cb(ngtcp2_conn*, void* user_data) {
    auto* c = static_cast<Conn*>(user_data);
    LOG("[server] Handshake completed with " << peer_key_v6(c->peer));
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn*, uint32_t, int64_t sid,
                               uint64_t, const uint8_t* data, size_t datalen,
                               void* user_data, void*) {
    auto* c = static_cast<Conn*>(user_data);
    if (c->closing) return 0;

    std::string s(reinterpret_cast<const char*>(data), datalen);

    std::cout << s;
    std::cout.flush();

    c->pending_echo.push_back(Conn::Pending{sid, std::move(s)});
    return 0;
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

static seastar::future<> flush_echo_and_packets(conn_ptr c, sock_ptr sock) {
    if (!c || !sock || !c->conn || c->closing) return seastar::make_ready_future<>();

    return seastar::do_with(std::array<uint8_t, MAX_UDP_OUT>{}, [c, sock](auto& outbuf) {
        return seastar::repeat([c, sock, &outbuf]() -> seastar::future<seastar::stop_iteration> {
            if (!c->conn || c->closing) {
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
            }

            if (!c->pending_echo.empty()) {
                auto item = std::move(c->pending_echo.back());
                c->pending_echo.pop_back();

                ngtcp2_path path{};
                ngtcp2_pkt_info pi{};
                std::memset(&pi, 0, sizeof(pi));
                c->fill_path(path);

                ngtcp2_vec vec;
                vec.base = (uint8_t*)item.data.data();
                vec.len  = item.data.size();

                ngtcp2_ssize ndatalen = 0;
                ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
                    c->conn, &path, &pi,
                    outbuf.data(), outbuf.size(),
                    &ndatalen,
                    0,
                    item.sid,
                    &vec, 1,
                    now_ns()
                );

                if (nwrite > 0) {
                    auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
                    std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);

                    auto p = seastar::net::packet(std::move(tb));

                    return sock->send_to(c->peer, std::move(p)).then([] {
                        return seastar::stop_iteration::no;
                    });
                }

                c->pending_echo.push_back(std::move(item));
            }

            ngtcp2_path path{};
            ngtcp2_pkt_info pi{};
            std::memset(&pi, 0, sizeof(pi));
            c->fill_path(path);

            ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
                c->conn, &path, &pi,
                outbuf.data(), outbuf.size(),
                now_ns()
            );

            if (nwrite == 0) {
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
            }
            if (nwrite < 0) {
                if (nwrite != NGTCP2_ERR_DRAINING && nwrite != NGTCP2_ERR_WRITE_MORE) {
                    LOG("[server] write_pkt error: " << ngtcp2_strerror((int)nwrite));
                }
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::yes);
            }

            auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
            std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);

            auto p = seastar::net::packet(std::move(tb));

            return sock->send_to(c->peer, std::move(p)).then([] {
                return seastar::stop_iteration::no;
            });
        });
    }).handle_exception([c](std::exception_ptr ep) {
        c->closing = true;
        try { std::rethrow_exception(ep); }
        catch (const std::exception& e) { LOG("[server] flush exception: " << e.what()); }
        return seastar::make_ready_future<>();
    });
}

static void init_tls_for_conn(Conn& c) {
    int grv = gnutls_certificate_allocate_credentials(&c.cred);
    if (grv < 0) throw std::runtime_error(std::string("gnutls_certificate_allocate_credentials: ") + gnutls_strerror(grv));

    grv = gnutls_certificate_set_x509_key_file(c.cred, CERT_FILE, KEY_FILE, GNUTLS_X509_FMT_PEM);
    if (grv < 0) throw std::runtime_error(std::string("gnutls_certificate_set_x509_key_file: ") + gnutls_strerror(grv));

    grv = gnutls_init(&c.tls, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA);
    if (grv < 0) throw std::runtime_error(std::string("gnutls_init: ") + gnutls_strerror(grv));

    grv = gnutls_credentials_set(c.tls, GNUTLS_CRD_CERTIFICATE, c.cred);
    if (grv < 0) throw std::runtime_error(std::string("gnutls_credentials_set: ") + gnutls_strerror(grv));

    const char* errpos = nullptr;
    grv = gnutls_priority_set_direct(c.tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", &errpos);
    if (grv < 0) {
        std::string where = errpos ? errpos : "(unknown)";
        throw std::runtime_error("gnutls_priority_set_direct at " + where + ": " + gnutls_strerror(grv));
    }

    const gnutls_datum_t alpns[] = {
        {(unsigned char*)"hq-interop", 9},
        {(unsigned char*)"h3", 2},
    };
    gnutls_alpn_set_protocols(c.tls, alpns, 2, 0);

    if (ngtcp2_crypto_gnutls_configure_server_session(c.tls) != 0) {
        throw std::runtime_error("ngtcp2_crypto_gnutls_configure_server_session failed");
    }

    c.conn_ref.get_conn  = get_conn;
    c.conn_ref.user_data = nullptr;
    gnutls_session_set_ptr(c.tls, &c.conn_ref);
}

static void init_ngtcp2_for_conn(Conn& c, const uint8_t* pkt, size_t pktlen) {
    ngtcp2_version_cid vc{};
    int rv = ngtcp2_pkt_decode_version_cid(&vc, pkt, pktlen, NGTCP2_MAX_CIDLEN);
    if (rv != 0) {
        throw std::runtime_error(std::string("ngtcp2_pkt_decode_version_cid: ") + ngtcp2_strerror(rv));
    }

    ngtcp2_cid dcid{};
    dcid.datalen = vc.scidlen;
    std::memcpy(dcid.data, vc.scid, vc.scidlen);

    ngtcp2_cid odcid{};
    odcid.datalen = vc.dcidlen;
    std::memcpy(odcid.data, vc.dcid, vc.dcidlen);

    ngtcp2_cid scid{};
    scid.datalen = 8;
    for (size_t i = 0; i < scid.datalen; ++i) scid.data[i] = (uint8_t)std::rand();

    ngtcp2_callbacks callbacks{};
    callbacks.recv_client_initial      = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_retry               = ngtcp2_crypto_recv_retry_cb;

    callbacks.recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt                  = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt                  = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask                  = ngtcp2_crypto_hp_mask_cb;
    callbacks.update_key               = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;

    callbacks.rand                    = rand_cb;
    callbacks.get_new_connection_id   = get_new_connection_id_cb;
    callbacks.get_path_challenge_data = get_path_challenge_data_cb;

    callbacks.recv_stream_data        = recv_stream_data_cb;
    callbacks.handshake_completed     = handshake_completed_cb;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();

    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);

    params.original_dcid_present = 1;
    params.original_dcid = odcid;

    params.initial_max_stream_data_bidi_local  = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data                    = 4 * 1024 * 1024;
    params.initial_max_streams_bidi            = 128;
    params.max_idle_timeout                    = 60 * 1000;
    params.active_connection_id_limit          = NGTCP2_DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;

    ngtcp2_path path{};
    c.fill_path(path);

    rv = ngtcp2_conn_server_new(
        &c.conn,
        &dcid, &scid,
        &path,
        NGTCP2_PROTO_VER_V1,
        &callbacks, &settings, &params,
        &g_mem,
        &c
    );
    if (rv != 0) {
        throw std::runtime_error(std::string("ngtcp2_conn_server_new: ") + ngtcp2_strerror(rv));
    }

    ngtcp2_conn_set_tls_native_handle(c.conn, c.tls);
    c.conn_ref.user_data = c.conn;
}

// Seastar-owned server state
struct ServerState {
    sock_ptr sock;
    seastar::socket_address listen_addr;
    std::unordered_map<std::string, conn_ptr> conns;
};

// Seastar receive loop
static seastar::future<> server_loop(seastar::lw_shared_ptr<ServerState> st) {
    // Seastar repeat loop returning a future.
    return seastar::repeat([st]() -> seastar::future<seastar::stop_iteration> {
        // Async receive chained with then().
        return st->sock->recv_one().then([st](seastar::net::datagram d) -> seastar::future<seastar::stop_iteration> {
            auto peer = d.get_src();
            auto key  = peer_key_v6(peer);

            auto& pkt = d.get_data();
            auto tb   = packet_to_tb(pkt);

            conn_ptr c;
            auto it = st->conns.find(key);
            if (it == st->conns.end()) {
                // Lightweight Seastar shared pointer for shard-local ownership.
                auto nc = seastar::make_lw_shared<Conn>();
                nc->peer = peer;

                sa_to_storage_v6(st->listen_addr, nc->local_ss, nc->local_ss_len);
                sa_to_storage_v6(peer, nc->peer_ss, nc->peer_ss_len);

                try {
                    init_tls_for_conn(*nc);
                    init_ngtcp2_for_conn(*nc, (const uint8_t*)tb.get(), tb.size());
                    LOG("[server] new conn from " << key);
                } catch (const std::exception& e) {
                    LOG("[server] init failed for " << key << ": " << e.what());
                    // Ready future for control flow without blocking.
                    return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::no);
                }

                st->conns.emplace(key, nc);
                c = nc;
            } else {
                c = it->second;
            }

            if (!c->conn || c->closing) {
                // Ready future used to continue the reactor loop.
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::no);
            }

            ngtcp2_path rpath{};
            ngtcp2_pkt_info pi{};
            std::memset(&pi, 0, sizeof(pi));
            c->fill_path(rpath);

            int rv = ngtcp2_conn_read_pkt(
                c->conn, &rpath, &pi,
                (const uint8_t*)tb.get(), tb.size(),
                now_ns()
            );

            if (rv < 0) {
                LOG("[server] read_pkt(" << key << "): " << ngtcp2_strerror(rv));
                c->closing = true;
                // Ready future to keep looping after marking connection closed.
                return seastar::make_ready_future<seastar::stop_iteration>(seastar::stop_iteration::no);
            }

            // Future-returning flush chained to keep progress.
            return flush_echo_and_packets(c, st->sock).then([] {
                return seastar::stop_iteration::no;
            });
        });
    });
}

// Seastar timer-driven maintenance loop
static seastar::future<> timeout_loop(seastar::lw_shared_ptr<ServerState> st) {
    // Periodic Seastar loop driven by futures.
    return seastar::repeat([st]() -> seastar::future<seastar::stop_iteration> {
        // Non-blocking sleep returning a future.
        return seastar::sleep(std::chrono::milliseconds(10)).then([st] {
            std::vector<seastar::future<>> futs;
            futs.reserve(st->conns.size());

            for (auto& [k, c] : st->conns) {
                if (!c || !c->conn || c->closing) continue;

                int rv = ngtcp2_conn_handle_expiry(c->conn, now_ns());
                if (rv < 0 && rv != NGTCP2_ERR_IDLE_CLOSE) {
                    LOG("[server] handle_expiry(" << k << "): " << ngtcp2_strerror(rv));
                    c->closing = true;
                    continue;
                }
                // Collect per-connection futures for coordinated completion.
                futs.push_back(flush_echo_and_packets(c, st->sock));
            }

            // Ready future for empty workset.
            if (futs.empty()) return seastar::make_ready_future<>();
            // Aggregate futures and return a single future.
            return seastar::when_all_succeed(futs.begin(), futs.end()).discard_result();
        }).then([] {
            return seastar::stop_iteration::no;
        });
    });
}

int main(int argc, char** argv) {
    std::srand((unsigned)time(nullptr));

    if (gnutls_global_init() < 0) {
        std::cerr << "gnutls_global_init failed\n";
        return 1;
    }

    // Seastar application wrapper handling startup and reactor configuration.
    seastar::app_template app;
    // Seastar entry point returning a future<int>.
    int rc = app.run(argc, argv, []() -> seastar::future<int> {
        try {
            sockaddr_in6 a{};
            a.sin6_family = AF_INET6;
            a.sin6_port   = htons(LISTEN_PORT);
            if (inet_pton(AF_INET6, LISTEN_IP, &a.sin6_addr) != 1) {
                throw std::runtime_error("inet_pton failed for LISTEN_IP");
            }
            // Seastar socket_address used by the networking stack.
            seastar::socket_address listen_addr = seastar::socket_address(a);

            // Reactor-owned UDP channel from Seastar networking.
            auto ch = seastar::engine().net().make_bound_datagram_channel(listen_addr);
            // lw_shared_ptr wrapper for passing through futures.
            auto sock = seastar::make_lw_shared<SeastarDgramSocket>(std::move(ch));

            // Shared server state owned in the Seastar reactor.
            auto st = seastar::make_lw_shared<ServerState>();
            st->sock = sock;
            st->listen_addr = listen_addr;

            LOG("QUIC echo server (GnuTLS+Seastar) listening on [" << LISTEN_IP << "]:" << LISTEN_PORT);

            return seastar::when_all_succeed(
                server_loop(st),
                timeout_loop(st)
            // Combine both loops and return a completion future.
            ).discard_result().then([] {
                return 0;
            // Convert exceptions into a resolved failure future.
            }).handle_exception([](std::exception_ptr ep) {
                try { std::rethrow_exception(ep); }
                catch (const std::exception& e) { LOG("[server] exception: " << e.what()); }
                return seastar::make_ready_future<int>(1);
            });
        } catch (const std::exception& e) {
            LOG("[server] fatal: " << e.what());
            // Immediate failure encoded as a ready future.
            return seastar::make_ready_future<int>(1);
        }
    });

    gnutls_global_deinit();
    return rc;
}