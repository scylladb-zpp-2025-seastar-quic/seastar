
#include <arpa/inet.h>
#include <gnutls/gnutls.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
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
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

static constexpr const char *LISTEN_IP = "::1";
static constexpr uint16_t LISTEN_PORT = 4444;
static constexpr size_t MAX_UDP_OUT = 1200;

static constexpr size_t SERVER_CID_LEN = 8;
static constexpr const char *CERT_FILE = "server.crt";
static constexpr const char *KEY_FILE = "server.key";

#define LOG(x)                  \
    do {                        \
        std::cerr << x << "\n"; \
    } while (0)

static gnutls_certificate_credentials_t g_server_cred = nullptr;
static std::string g_cert_path = CERT_FILE;
static std::string g_key_path = KEY_FILE;

static void init_server_credentials_once() {
    if (g_server_cred) return;
    if (gnutls_certificate_allocate_credentials(&g_server_cred) < 0) {
        throw std::runtime_error(
            "gnutls_certificate_allocate_credentials failed");
    }
    if (gnutls_certificate_set_x509_key_file(g_server_cred, g_cert_path.c_str(),
                                             g_key_path.c_str(),
                                             GNUTLS_X509_FMT_PEM) < 0) {
        throw std::runtime_error("gnutls_certificate_set_x509_key_file failed");
    }
}

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

static ngtcp2_tstamp now_ns() {
    using namespace std::chrono;
    return duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

static void *my_malloc(size_t size, void *) { return std::malloc(size); }
static void my_free(void *ptr, void *) { std::free(ptr); }
static void *my_calloc(size_t n, size_t s, void *) { return std::calloc(n, s); }
static void *my_realloc(void *p, size_t s, void *) {
    return std::realloc(p, s);
}
static const ngtcp2_mem g_mem = {nullptr, my_malloc, my_free, my_calloc,
                                 my_realloc};

static void init_ngtcp2_addr(ngtcp2_addr *addr, const sockaddr *sa,
                             size_t len) {
    addr->addr = const_cast<sockaddr *>(sa);
    addr->addrlen = (socklen_t)len;
}

static void sa_to_storage_v6(const seastar::socket_address &sa,
                             sockaddr_storage &out, socklen_t &outlen) {
    std::memset(&out, 0, sizeof(out));
    auto in6 = sa.as_posix_sockaddr_in6();
    outlen = sizeof(sockaddr_in6);
    std::memcpy(&out, &in6, sizeof(sockaddr_in6));
}

static std::string ip_port_key_v6(const seastar::socket_address &sa) {
    auto in6 = sa.as_posix_sockaddr_in6();
    char buf[INET6_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET6, &in6.sin6_addr, buf, sizeof(buf));
    uint16_t port = ntohs(in6.sin6_port);
    return std::string(buf) + ":" + std::to_string(port);
}

[[maybe_unused]] static std::string cid_key(const uint8_t *p, size_t n) {
    return std::string(reinterpret_cast<const char *>(p), n);
}
[[maybe_unused]] static std::string cid_key(const ngtcp2_cid &cid) {
    return cid_key(cid.data, cid.datalen);
}
[[maybe_unused]] static std::string cid_hex(const uint8_t *p, size_t n) {
    static const char *h = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(h[(p[i] >> 4) & 0xF]);
        out.push_back(h[p[i] & 0xF]);
    }
    return out;
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
    seastar::socket_address local_address() const {
        return ch_.local_address();
    }

   private:
    seastar::net::datagram_channel ch_;
};

struct ServerState;

struct Conn {
    ServerState *st = nullptr;
    ngtcp2_conn *conn = nullptr;
    gnutls_session_t tls = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};

    seastar::socket_address peer{};
    sockaddr_storage local_ss{};
    socklen_t local_ss_len = 0;
    sockaddr_storage peer_ss{};
    socklen_t peer_ss_len = 0;

    bool closing = false;
    seastar::condition_variable timer_cv;

    std::unordered_set<std::string> mapped_dcids;
    std::string last_rx_dcid_hex;

    struct Pending {
        int64_t sid;
        std::string data;
    };
    std::vector<Pending> pending_echo;

    ~Conn() {
        timer_cv.broken();
        if (conn) ngtcp2_conn_del(conn);
        if (tls) gnutls_deinit(tls);
    }

    void fill_path(ngtcp2_path &p) {
        init_ngtcp2_addr(&p.local, (sockaddr *)&local_ss, local_ss_len);
        init_ngtcp2_addr(&p.remote, (sockaddr *)&peer_ss, peer_ss_len);
    }

    void reschedule() { timer_cv.signal(); }
};

using conn_ptr = seastar::lw_shared_ptr<Conn>;
using sock_ptr = seastar::lw_shared_ptr<SeastarDgramSocket>;

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref) {
    return (ngtcp2_conn *)conn_ref->user_data;
}

struct ServerState {
    sock_ptr sock;
    seastar::socket_address listen_addr;
    std::unordered_map<std::string, conn_ptr> by_dcid;
    std::vector<conn_ptr> conns;
};

static void map_dcid(ServerState &st, const conn_ptr &c, const uint8_t *dcid,
                     size_t dcid_len) {
    auto k = cid_key(dcid, dcid_len);
    st.by_dcid[k] = c;
    c->mapped_dcids.insert(std::move(k));
}
static void map_dcid(ServerState &st, const conn_ptr &c,
                     const ngtcp2_cid &cid) {
    map_dcid(st, c, cid.data, cid.datalen);
}
static void unmap_all_dcids(ServerState &st, const conn_ptr &c) {
    for (const auto &k : c->mapped_dcids) {
        auto it = st.by_dcid.find(k);
        if (it != st.by_dcid.end() && it->second == c) {
            st.by_dcid.erase(it);
        }
    }
    c->mapped_dcids.clear();
}
static void remove_conn(ServerState &st, const conn_ptr &c) {
    unmap_all_dcids(st, c);
    auto &v = st.conns;
    v.erase(std::remove(v.begin(), v.end(), c), v.end());
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *) {
    for (size_t i = 0; i < destlen; ++i) dest[i] = (uint8_t)std::rand();
}
static int get_new_connection_id_cb(ngtcp2_conn *, ngtcp2_cid *cid,
                                    uint8_t *token, size_t cidlen, void *) {
    cid->datalen = cidlen;
    for (size_t i = 0; i < cidlen; ++i) cid->data[i] = (uint8_t)std::rand();
    for (size_t i = 0; i < NGTCP2_STATELESS_RESET_TOKENLEN; ++i)
        token[i] = (uint8_t)std::rand();
    return 0;
}
static int get_path_challenge_data_cb(ngtcp2_conn *, uint8_t *data, void *) {
    for (size_t i = 0; i < 8; ++i) data[i] = (uint8_t)std::rand();
    return 0;
}
static int handshake_completed_cb(ngtcp2_conn *, void *user_data) {
    auto *c = static_cast<Conn *>(user_data);
    LOG("[server] Handshake completed with " << ip_port_key_v6(c->peer));
    return 0;
}
static int recv_stream_data_cb(ngtcp2_conn *, uint32_t, int64_t sid, uint64_t,
                               const uint8_t *data, size_t datalen,
                               void *user_data, void *) {
    auto *c = static_cast<Conn *>(user_data);
    if (c->closing) return 0;
    std::string s(reinterpret_cast<const char *>(data), datalen);
    std::cout << "[Client " << ip_port_key_v6(c->peer) << "]: " << s;
    if (!s.empty() && s.back() != '\n') std::cout << "\n";
    std::cout.flush();
    c->pending_echo.push_back(Conn::Pending{sid, std::move(s)});
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

static void init_tls_for_conn(Conn &c) {
    if (!g_server_cred) throw std::runtime_error("no credentials");
    int grv = gnutls_init(&c.tls, GNUTLS_SERVER | GNUTLS_ENABLE_EARLY_DATA);
    if (grv < 0) throw std::runtime_error("gnutls_init failed");
    gnutls_credentials_set(c.tls, GNUTLS_CRD_CERTIFICATE, g_server_cred);
    gnutls_priority_set_direct(c.tls, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr);
    const gnutls_datum_t alpns[] = {{(unsigned char *)"hq-interop", 9},
                                    {(unsigned char *)"h3", 2}};
    gnutls_alpn_set_protocols(c.tls, alpns, 2, 0);
    ngtcp2_crypto_gnutls_configure_server_session(c.tls);
    c.conn_ref.get_conn = get_conn;
    c.conn_ref.user_data = nullptr;
    gnutls_session_set_ptr(c.tls, &c.conn_ref);
}

static void init_ngtcp2_for_conn(Conn &c, const uint8_t *pkt, size_t pktlen,
                                 ngtcp2_cid &out_server_scid,
                                 ngtcp2_cid &out_client_odcid) {
    ngtcp2_version_cid vc{};
    ngtcp2_pkt_decode_version_cid(&vc, pkt, pktlen, NGTCP2_MAX_CIDLEN);
    ngtcp2_cid dcid{};
    dcid.datalen = vc.scidlen;
    std::memcpy(dcid.data, vc.scid, vc.scidlen);
    ngtcp2_cid odcid{};
    odcid.datalen = vc.dcidlen;
    std::memcpy(odcid.data, vc.dcid, vc.dcidlen);
    ngtcp2_cid scid{};
    scid.datalen = SERVER_CID_LEN;
    for (size_t i = 0; i < scid.datalen; ++i)
        scid.data[i] = (uint8_t)std::rand();

    ngtcp2_callbacks callbacks{};
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_retry = ngtcp2_crypto_recv_retry_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.update_key = ngtcp2_crypto_update_key_cb;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx =
        ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    callbacks.rand = rand_cb;
    callbacks.get_new_connection_id = get_new_connection_id_cb;
    callbacks.get_path_challenge_data = get_path_challenge_data_cb;
    callbacks.recv_stream_data = recv_stream_data_cb;
    callbacks.handshake_completed = handshake_completed_cb;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = now_ns();
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.original_dcid_present = 1;
    params.original_dcid = odcid;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data = 4 * 1024 * 1024;
    params.initial_max_streams_bidi = 128;
    params.max_idle_timeout = 0;

    ngtcp2_path path{};
    c.fill_path(path);
    ngtcp2_conn_server_new(&c.conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1,
                           &callbacks, &settings, &params, &g_mem, &c);
    ngtcp2_conn_set_tls_native_handle(c.conn, c.tls);
    c.conn_ref.user_data = c.conn;
    out_server_scid = scid;
    out_client_odcid = odcid;
}

static seastar::future<> flush_echo_and_packets(const conn_ptr &c,
                                                const sock_ptr &sock) {
    if (!c || !sock || !c->conn || c->closing) co_return;

    std::vector<uint8_t> outbuf(MAX_UDP_OUT);
    bool did_write_something = false;

    try {
        while (true) {
            if (!c->conn || c->closing) break;
            bool did_send = false;

            if (!c->pending_echo.empty()) {
                auto item = std::move(c->pending_echo.back());
                c->pending_echo.pop_back();

                ngtcp2_path path{};
                c->fill_path(path);
                ngtcp2_pkt_info pi{};
                std::memset(&pi, 0, sizeof(pi));
                ngtcp2_vec vec;
                vec.base = (uint8_t *)item.data.data();
                vec.len = item.data.size();
                ngtcp2_ssize ndatalen = 0;
                ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
                    c->conn, &path, &pi, outbuf.data(), outbuf.size(),
                    &ndatalen, 0, item.sid, &vec, 1, now_ns());

                if (nwrite > 0) {
                    auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
                    std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
                    co_await sock->send_to(c->peer,
                                           seastar::net::packet(std::move(tb)));
                    did_send = true;
                    did_write_something = true;
                } else {
                    c->pending_echo.push_back(std::move(item));
                }
            }

            ngtcp2_path path{};
            c->fill_path(path);
            ngtcp2_pkt_info pi{};
            std::memset(&pi, 0, sizeof(pi));
            ngtcp2_ssize nwrite = ngtcp2_conn_write_pkt(
                c->conn, &path, &pi, outbuf.data(), outbuf.size(), now_ns());

            if (nwrite < 0) {
                if (nwrite != NGTCP2_ERR_DRAINING &&
                    nwrite != NGTCP2_ERR_WRITE_MORE) {
                    LOG("[server] write_pkt err: "
                        << ngtcp2_strerror((int)nwrite));
                    c->closing = true;
                }
                break;
            }
            if (nwrite == 0) {
                if (!did_send) break;
                continue;
            }

            if (nwrite > (ngtcp2_ssize)MAX_UDP_OUT) {
                LOG("[server] FATAL: packet too big: " << nwrite);
                break;
            }

            auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
            std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
            co_await sock->send_to(c->peer,
                                   seastar::net::packet(std::move(tb)));
            did_write_something = true;
        }
    } catch (const std::exception &e) {
        c->closing = true;
        LOG("[server] flush exc: " << e.what());
    }

    if (did_write_something && !c->closing) {
        c->reschedule();
    }
}

static seastar::future<> connection_timer_loop(conn_ptr c, sock_ptr sock) {
    while (!c->closing) {
        co_await flush_echo_and_packets(c, sock);
        if (c->closing) break;

        auto now = now_ns();
        auto expiry = ngtcp2_conn_get_expiry(c->conn);

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

        now = now_ns();
        if (ngtcp2_conn_get_expiry(c->conn) <= now) {
            int rv = ngtcp2_conn_handle_expiry(c->conn, now);
            if (rv < 0) {
                if (rv == NGTCP2_ERR_IDLE_CLOSE) {
                    LOG("[server] Client " << ip_port_key_v6(c->peer)
                                           << " disconnected (idle timeout).");
                } else if (rv != NGTCP2_ERR_DRAINING) {
                    LOG("[server] handle_expiry error: "
                        << ngtcp2_strerror(rv));
                }
                c->closing = true;
            }
        }
    }

    if (c->st) {
        remove_conn(*c->st, c);
    }
}

static seastar::future<> handle_datagram(
    const seastar::lw_shared_ptr<ServerState> &st, seastar::net::datagram d) {
    auto peer = d.get_src();
    auto &pkt = d.get_data();
    auto tb = packet_to_tb(pkt);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(tb.get());
    size_t n = tb.size();

    auto parsed = parse_dcid_quic_v1(p, n, SERVER_CID_LEN);
    if (!parsed.ok) co_return;

    conn_ptr c;
    auto it = st->by_dcid.find(cid_key(parsed.dcid.data(), parsed.dcid_len));
    if (it != st->by_dcid.end()) c = it->second;

    if (!c) {
        if (!parsed.long_header || parsed.long_type != QuicLongType::Initial)
            co_return;

        auto nc = seastar::make_lw_shared<Conn>();
        nc->st = st.get();
        nc->peer = peer;
        sa_to_storage_v6(st->listen_addr, nc->local_ss, nc->local_ss_len);
        sa_to_storage_v6(peer, nc->peer_ss, nc->peer_ss_len);

        ngtcp2_cid server_scid{}, client_odcid{};
        try {
            init_tls_for_conn(*nc);
            init_ngtcp2_for_conn(*nc, p, n, server_scid, client_odcid);
        } catch (...) {
            co_return;
        }

        map_dcid(*st, nc, client_odcid);
        map_dcid(*st, nc, server_scid);
        st->conns.push_back(nc);
        c = nc;

        LOG("[server] new conn: peer=" << ip_port_key_v6(peer));
        (void)connection_timer_loop(c, st->sock).or_terminate();
    }

    if (!c || !c->conn || c->closing) co_return;
    c->last_rx_dcid_hex = cid_hex(parsed.dcid.data(), parsed.dcid_len);

    ngtcp2_path rpath{};
    c->fill_path(rpath);
    ngtcp2_pkt_info pi{};
    std::memset(&pi, 0, sizeof(pi));

    int rv = ngtcp2_conn_read_pkt(c->conn, &rpath, &pi, p, n, now_ns());
    if (rv < 0) {
        if (rv == NGTCP2_ERR_DRAINING) {
            LOG("[server] Client " << ip_port_key_v6(c->peer)
                                   << " disconnected.");
        } else {
            LOG("[server] read error: " << ngtcp2_strerror(rv));
        }
        c->closing = true;
    }

    c->reschedule();
}

static seastar::future<> server_loop(seastar::lw_shared_ptr<ServerState> st) {
    while (true) {
        try {
            auto d = co_await st->sock->recv_one();
            co_await handle_datagram(st, std::move(d));
        } catch (...) {
        }
    }
}

int main(int argc, char **argv) {
    std::srand((unsigned)time(nullptr));
    if (gnutls_global_init() < 0) return 1;
    parse_tls_args(argc, argv);
    try {
        init_server_credentials_once();
    } catch (...) {
        return 1;
    }

    seastar::app_template app;
    int rc = app.run(argc, argv, []() -> seastar::future<int> {
        sockaddr_in6 a{};
        a.sin6_family = AF_INET6;
        a.sin6_port = htons(LISTEN_PORT);
        inet_pton(AF_INET6, LISTEN_IP, &a.sin6_addr);
        auto sock = seastar::make_lw_shared<SeastarDgramSocket>(
            seastar::engine().net().make_bound_datagram_channel(
                seastar::socket_address(a)));
        auto st = seastar::make_lw_shared<ServerState>();
        st->sock = sock;
        st->listen_addr = seastar::socket_address(a);

        LOG("QUIC server (Serialized Event-Loop) listening on port "
            << LISTEN_PORT);
        co_await server_loop(st);
        co_return 0;
    });

    gnutls_certificate_free_credentials(g_server_cred);
    gnutls_global_deinit();
    return rc;
}