/*
 * Shared body for rpc_modified and rpc_quic unit tests.
 *
 * The including TU must already have included exactly one of:
 *   <seastar/rpc/rpc_modified.hh>
 *   <seastar/rpc/rpc_quic.hh>
 * (both expose the seastar::rpc::* surface used here, but define
 *  conflicting symbols, so they cannot be linked together.)
 */

#include "loopback_socket.hh"

#include <seastar/rpc/rpc_types.hh>
#include <seastar/rpc/lz4_compressor.hh>
#include <seastar/rpc/multi_algo_compressor_factory.hh>
#include <seastar/core/scheduling.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/testing/thread_test_case.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/thread.hh>
#include <seastar/core/loop.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/util/closeable.hh>
#include <seastar/util/defer.hh>
#include <seastar/util/log.hh>

using namespace seastar;

// ---------- minimal serializer (int / sstring) ----------

struct serializer {};

template <typename T, typename Output>
inline void write_arith(Output& out, T v) {
    out.write(reinterpret_cast<const char*>(&v), sizeof(T));
}

template <typename T, typename Input>
inline T read_arith(Input& in) {
    T v;
    in.read(reinterpret_cast<char*>(&v), sizeof(T));
    return v;
}

template <typename Output> inline void write(serializer, Output& o, int32_t v) { write_arith(o, v); }
template <typename Output> inline void write(serializer, Output& o, uint32_t v) { write_arith(o, v); }
template <typename Output> inline void write(serializer, Output& o, int64_t v) { write_arith(o, v); }
template <typename Output> inline void write(serializer, Output& o, uint64_t v) { write_arith(o, v); }
template <typename Input> inline int32_t  read(serializer, Input& i, rpc::type<int32_t>)  { return read_arith<int32_t>(i); }
template <typename Input> inline uint32_t read(serializer, Input& i, rpc::type<uint32_t>) { return read_arith<uint32_t>(i); }
template <typename Input> inline int64_t  read(serializer, Input& i, rpc::type<int64_t>)  { return read_arith<int64_t>(i); }
template <typename Input> inline uint64_t read(serializer, Input& i, rpc::type<uint64_t>) { return read_arith<uint64_t>(i); }

template <typename Output>
inline void write(serializer, Output& o, const sstring& v) {
    write_arith(o, uint32_t(v.size()));
    o.write(v.c_str(), v.size());
}
template <typename Input>
inline sstring read(serializer, Input& in, rpc::type<sstring>) {
    auto sz = read_arith<uint32_t>(in);
    sstring s = uninitialized_string(sz);
    in.read(s.data(), sz);
    return s;
}

using test_proto = rpc::protocol<serializer>;

// ---------- loopback wiring ----------

class lb_socket_impl final : public ::net::socket_impl {
    loopback_socket_impl _socket;
public:
    explicit lb_socket_impl(loopback_connection_factory& f) : _socket(f, nullptr) {}
    future<connected_socket> connect(socket_address sa, socket_address local, transport proto = transport::TCP) override {
        return _socket.connect(sa, local, proto);
    }
    void set_reuseaddr(bool) override {}
    bool get_reuseaddr() const override { return false; }
    void shutdown() override { _socket.shutdown(); }
};

// Hand-rolled environment that mirrors rpc_test_env, but on a single shard
// (sharded<> is overkill for our smoke tests and complicates teardown when
// the underlying RPC implementation is buggy).
struct rpc_env {
    // The test server lives on shard 0 only; pin the loopback factory to 1
    // shard so connections aren't round-robined to shards that have no server
    // (otherwise -c2+ would hang on connect).
    loopback_connection_factory lcf{1};
    test_proto proto;
    test_proto::server server;
    std::vector<int> handlers;

    rpc_env(rpc::resource_limits rl = {}, rpc::server_options so = {})
        : proto(serializer{})
        , server(proto, so, lcf.get_server_socket(), rl)
    {}

    ~rpc_env() = default;

    seastar::socket make_socket() {
        return seastar::socket(std::make_unique<lb_socket_impl>(lcf));
    }

    template <typename Func>
    void register_handler(int t, Func&& f) {
        proto.register_handler(t, std::forward<Func>(f));
        handlers.push_back(t);
    }

    template <typename Func>
    void register_handler(int t, scheduling_group sg, Func&& f) {
        proto.register_handler(t, sg, std::forward<Func>(f));
        handlers.push_back(t);
    }

    future<> stop() {
        std::vector<int> hs = std::move(handlers);
        return parallel_for_each(hs, [this] (int t) {
            return proto.unregister_handler(t);
        }).finally([this] {
            return server.stop();
        }).finally([this] {
            return lcf.destroy_all_shards();
        });
    }
};

// Helper that owns env + (optionally) a client and tears down in the right order.
template <typename Body>
future<> with_env(Body&& body, rpc::resource_limits rl = {}, rpc::server_options so = {}) {
    return seastar::async([body = std::forward<Body>(body), rl = std::move(rl), so = std::move(so)] () mutable {
        auto env = std::make_unique<rpc_env>(rl, so);
        std::exception_ptr ep;
        try {
            body(*env);
        } catch (...) {
            ep = std::current_exception();
        }
        env->stop().get();
        if (ep) { std::rethrow_exception(ep); }
    });
}

// ============================================================
// Tests
// ============================================================

SEASTAR_TEST_CASE(test_basic_call) {
    return with_env([] (rpc_env& env) {
        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto sum = env.proto.make_client<int (int, int)>(1);
        BOOST_REQUIRE_EQUAL(sum(c, 2, 3).get(), 5);
        BOOST_REQUIRE_EQUAL(sum(c, -7, 7).get(), 0);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_void_return) {
    return with_env([] (rpc_env& env) {
        bool called = false;
        env.register_handler(2, [&called] (int x) {
            called = (x == 42);
            return make_ready_future<>();
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<void (int)>(2);
        call(c, 42).get();
        BOOST_REQUIRE(called);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_string_payload) {
    return with_env([] (rpc_env& env) {
        env.register_handler(3, [] (sstring s) {
            return make_ready_future<sstring>(s + sstring("!"));
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<sstring (sstring)>(3);
        BOOST_REQUIRE_EQUAL(call(c, sstring("hi")).get(), sstring("hi!"));
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_remote_verb_throws) {
    return with_env([] (rpc_env& env) {
        env.register_handler(4, [] () -> future<int> {
            throw std::runtime_error("boom");
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int ()>(4);
        BOOST_REQUIRE_THROW(call(c).get(), rpc::remote_verb_error);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_unknown_verb) {
    return with_env([] (rpc_env& env) {
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int ()>(99);
        BOOST_REQUIRE_THROW(call(c).get(), rpc::unknown_verb_error);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_concurrent_calls) {
    return with_env([] (rpc_env& env) {
        env.register_handler(5, [] (int x) {
            return seastar::sleep(std::chrono::milliseconds(2)).then([x] {
                return make_ready_future<int>(x * x);
            });
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(5);
        std::vector<future<int>> fs;
        for (int i = 0; i < 32; ++i) {
            fs.push_back(call(c, i));
        }
        int got = 0;
        for (int i = 0; i < 32; ++i) {
            got += fs[i].get();
        }
        // sum_{i=0..31} i^2 = 31*32*63/6 = 10416
        BOOST_REQUIRE_EQUAL(got, 10416);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_unregister_handler) {
    return with_env([] (rpc_env& env) {
        env.register_handler(6, [] () { return make_ready_future<int>(7); });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int ()>(6);
        BOOST_REQUIRE_EQUAL(call(c).get(), 7);
        // pop the handler so env.stop() does not double-unregister
        env.handlers.erase(std::find(env.handlers.begin(), env.handlers.end(), 6));
        env.proto.unregister_handler(6).get();
        BOOST_REQUIRE_THROW(call(c).get(), rpc::unknown_verb_error);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_message_too_big) {
    rpc::resource_limits rl{0, 1, 100};
    return with_env([] (rpc_env& env) {
        bool handler_ran = false;
        env.register_handler(7, [&handler_ran] (sstring) {
            handler_ran = true;
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<void (sstring)>(7);
        // Message size > max_memory => server must reject without invoking handler.
        BOOST_CHECK_THROW(call(c, uninitialized_string(101)).get(), std::runtime_error);
        BOOST_REQUIRE(!handler_ran);
        c.stop().get();
    }, rl);
}

SEASTAR_TEST_CASE(test_client_stop_aborts_pending) {
    return with_env([] (rpc_env& env) {
        // Handler blocks on an explicit promise (released in finally) rather
        // than a long sleep, so teardown is instant once the client stops.
        auto release = make_lw_shared<promise<>>();
        env.register_handler(8, [release] () {
            return release->get_future().then([] { return make_ready_future<int>(0); });
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int ()>(8);
        auto f = call(c);
        seastar::sleep(std::chrono::milliseconds(20)).get();  // let the call reach the server
        c.stop().get();
        BOOST_CHECK_THROW(f.get(), std::exception);
        release->set_value();  // let the server-side handler finish so stop() drains fast
    });
}

SEASTAR_TEST_CASE(test_cancel_send) {
    using namespace std::chrono_literals;
    return with_env([] (rpc_env& env) {
        bool ran = false;
        env.register_handler(9, [&ran] {
            ran = true;
            return make_ready_future<>();
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<void ()>(9);
        promise<> hold;
        rpc::cancellable cancel;
        c.suspend_for_testing(hold);  // block the sender queue
        auto f = call(c, cancel);
        cancel.cancel();
        hold.set_value();
        BOOST_CHECK_THROW(f.get(), rpc::canceled_error);
        BOOST_REQUIRE(!ran);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_no_wait_one_way) {
    return with_env([] (rpc_env& env) {
        promise<> handler_called;
        auto fut = handler_called.get_future();
        env.register_handler(10, [&handler_called] (int x) -> future<rpc::no_wait_type> {
            if (x == 5) handler_called.set_value();
            return make_ready_future<rpc::no_wait_type>(rpc::no_wait);
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<rpc::no_wait_type (int)>(10);
        call(c, 5).get();           // returns immediately on the wire
        fut.get();                  // server-side observed the call
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_has_handler) {
    return with_env([] (rpc_env& env) {
        BOOST_REQUIRE(!env.proto.has_handlers());
        env.register_handler(11, [] { return make_ready_future<>(); });
        BOOST_REQUIRE(env.proto.has_handlers());
        BOOST_REQUIRE(env.proto.has_handler(11));
        BOOST_REQUIRE(!env.proto.has_handler(12));
    });
}

SEASTAR_TEST_CASE(test_isolation_cookie_invokes_resolver) {
    auto seen = make_lw_shared<int>(0);
    rpc::resource_limits rl;
    rl.isolate_connection = [seen] (sstring cookie) {
        if (cookie == sstring("special")) (*seen)++;
        return rpc::isolation_config{};
    };
    return with_env([] (rpc_env& env) {
        env.register_handler(13, [] (int x) { return make_ready_future<int>(x); });
        rpc::client_options co;
        co.isolation_cookie = "special";
        test_proto::client c(env.proto, co, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(13);
        BOOST_REQUIRE_EQUAL(call(c, 9).get(), 9);
        c.stop().get();
    }, std::move(rl)).then([seen] {
        BOOST_REQUIRE_GE(*seen, 1);
    });
}

SEASTAR_TEST_CASE(test_stats_counted) {
    return with_env([] (rpc_env& env) {
        env.register_handler(14, [] (int x) { return make_ready_future<int>(x + 1); });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(14);
        for (int i = 0; i < 5; ++i) {
            BOOST_REQUIRE_EQUAL(call(c, i).get(), i + 1);
        }
        auto s = c.get_stats();
        BOOST_REQUIRE_GE(s.sent_messages, 5u);
        BOOST_REQUIRE_GE(s.replied, 5u);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_reregister_throws) {
    return with_env([] (rpc_env& env) {
        env.register_handler(15, [] { return make_ready_future<>(); });
        BOOST_CHECK_THROW(
            env.proto.register_handler(15, [] { return make_ready_future<>(); }),
            std::runtime_error);
    });
}

SEASTAR_TEST_CASE(test_two_clients_same_server) {
    return with_env([] (rpc_env& env) {
        env.register_handler(16, [] (int x) { return make_ready_future<int>(x * 2); });
        test_proto::client c1(env.proto, {}, env.make_socket(), ipv4_addr());
        test_proto::client c2(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(16);
        BOOST_REQUIRE_EQUAL(call(c1, 3).get(), 6);
        BOOST_REQUIRE_EQUAL(call(c2, 5).get(), 10);
        c1.stop().get();
        c2.stop().get();
    });
}

// ============================================================
// Extended tests
// ============================================================

// Minimal LZ4 compressor factory (mirrors the one in rpc_test.cc).
struct test_cfactory : rpc::compressor::factory {
    mutable int negotiated = 0;
    const sstring _name = "LZ4";
    const sstring& supported() const override { return _name; }
    std::unique_ptr<rpc::compressor> negotiate(sstring feature, bool is_server) const override {
        if (feature == _name) {
            negotiated++;
            return std::make_unique<rpc::lz4_compressor>();
        }
        return nullptr;
    }
};

SEASTAR_TEST_CASE(test_send_timeout) {
    return with_env([] (rpc_env& env) {
        // Handler blocks until released; the client's short timeout must fire
        // first. Releasing in finally keeps teardown instant.
        auto release = make_lw_shared<promise<>>();
        env.register_handler(20, [release] (int v) {
            return release->get_future().then([v] { return make_ready_future<int>(v); });
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(20);
        auto start = std::chrono::steady_clock::now();
        BOOST_CHECK_THROW(call(c, std::chrono::milliseconds(100), 1).get(),
                          rpc::timeout_error);
        BOOST_REQUIRE(std::chrono::steady_clock::now() - start < std::chrono::seconds(2));
        c.stop().get();
        release->set_value();
    });
}

SEASTAR_TEST_CASE(test_scheduling_group_per_handler) {
    return with_env([] (rpc_env& env) {
        auto sg = create_scheduling_group("rpc_test_sg", 100).get();
        auto cleanup = defer([sg] () noexcept { destroy_scheduling_group(sg).get(); });
        env.register_handler(21, sg, [] () {
            return make_ready_future<unsigned>(
                internal::scheduling_group_index(current_scheduling_group()));
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<unsigned ()>(21);
        BOOST_REQUIRE_EQUAL(call(c).get(), internal::scheduling_group_index(sg));
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_abort_connection_from_handler) {
    return with_env([] (rpc_env& env) {
        auto arrived = make_lw_shared<int>(0);
        env.register_handler(22, [arrived] (rpc::client_info& ci, int x) {
            BOOST_REQUIRE_EQUAL(x, (*arrived)++);
            if (*arrived == 2) {
                ci.server.abort_connection(ci.conn_id);
            }
            return 0;
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(22);
        BOOST_REQUIRE_EQUAL(call(c, 0).get(), 0);
        BOOST_CHECK_THROW(call(c, 1).get(), rpc::closed_error);
        BOOST_CHECK_THROW(call(c, 2).get(), rpc::closed_error);
        BOOST_REQUIRE_EQUAL(*arrived, 2);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_client_info_auxiliary) {
    return with_env([] (rpc_env& env) {
        rpc::client_info info{.server{env.server}, .conn_id{rpc::connection_id::make_id(0, 0)}};
        const rpc::client_info& cinfo = info;
        info.attach_auxiliary("k", 7);
        BOOST_REQUIRE_EQUAL(cinfo.retrieve_auxiliary<int>("k"), 7);
        info.retrieve_auxiliary<int>("k") = 9;
        BOOST_REQUIRE_EQUAL(cinfo.retrieve_auxiliary<int>("k"), 9);
        BOOST_REQUIRE_EQUAL(cinfo.retrieve_auxiliary_opt<int>("missing"),
                            static_cast<const int*>(nullptr));
    });
}

SEASTAR_TEST_CASE(test_connection_id_format) {
    rpc::connection_id cid = rpc::connection_id::make_id(0x123, 1);
    BOOST_REQUIRE_EQUAL(format("{}", cid), sstring("1230001"));
    return make_ready_future<>();
}

SEASTAR_TEST_CASE(test_multiple_distinct_verbs) {
    return with_env([] (rpc_env& env) {
        env.register_handler(30, [] (int a, int b) { return make_ready_future<int>(a + b); });
        env.register_handler(31, [] (int a, int b) { return make_ready_future<int>(a * b); });
        env.register_handler(32, [] (sstring s) { return make_ready_future<sstring>(s + s); });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto add = env.proto.make_client<int (int, int)>(30);
        auto mul = env.proto.make_client<int (int, int)>(31);
        auto dup = env.proto.make_client<sstring (sstring)>(32);
        BOOST_REQUIRE_EQUAL(add(c, 4, 5).get(), 9);
        BOOST_REQUIRE_EQUAL(mul(c, 4, 5).get(), 20);
        BOOST_REQUIRE_EQUAL(dup(c, sstring("ab")).get(), sstring("abab"));
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_large_payload_roundtrip) {
    return with_env([] (rpc_env& env) {
        env.register_handler(33, [] (sstring s) {
            return make_ready_future<uint64_t>(s.size());
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<uint64_t (sstring)>(33);
        sstring big(256 * 1024, 'x');
        BOOST_REQUIRE_EQUAL(call(c, big).get(), big.size());
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_tuple_return) {
    return with_env([] (rpc_env& env) {
        env.register_handler(34, [] (int x) {
            return make_ready_future<rpc::tuple<int, sstring>>(
                rpc::tuple<int, sstring>(x + 1, sstring("ok")));
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<rpc::tuple<int, sstring> (int)>(34);
        auto [n, s] = call(c, 41).get();
        BOOST_REQUIRE_EQUAL(n, 42);
        BOOST_REQUIRE_EQUAL(s, sstring("ok"));
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_compression_lz4_roundtrip) {
    auto factory = make_lw_shared<test_cfactory>();
    rpc::server_options so;
    so.compressor_factory = factory.get();
    return with_env([factory] (rpc_env& env) {
        env.register_handler(35, [] (sstring s) {
            return make_ready_future<sstring>(s + sstring("-z"));
        });
        rpc::client_options co;
        co.compressor_factory = factory.get();
        test_proto::client c(env.proto, co, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<sstring (sstring)>(35);
        BOOST_REQUIRE_EQUAL(call(c, sstring("payload")).get(), sstring("payload-z"));
        c.stop().get();
    }, {}, std::move(so)).then([factory] {
        // Both client and server must have negotiated the LZ4 compressor.
        BOOST_REQUIRE_GE(factory->negotiated, 2);
    });
}

SEASTAR_TEST_CASE(test_server_shutdown_then_stop) {
    return with_env([] (rpc_env& env) {
        env.register_handler(36, [] (int x) { return make_ready_future<int>(x); });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(36);
        BOOST_REQUIRE_EQUAL(call(c, 1).get(), 1);
        // shutdown() must precede stop(); after it, new calls must fail.
        env.server.shutdown().get();
        BOOST_CHECK_THROW(call(c, 2).get(), std::exception);
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_many_sequential_calls_ordering) {
    return with_env([] (rpc_env& env) {
        env.register_handler(37, [] (int x) { return make_ready_future<int>(x); });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(37);
        for (int i = 0; i < 200; ++i) {
            BOOST_REQUIRE_EQUAL(call(c, i).get(), i);
        }
        c.stop().get();
    });
}

SEASTAR_TEST_CASE(test_handler_receives_client_info) {
    return with_env([] (rpc_env& env) {
        // The handler just records that it received a client_info and the
        // argument; never assert inside a handler (a failing BOOST_* there
        // aborts the process instead of failing the test).
        auto got_arg = make_lw_shared<int>(-1);
        env.register_handler(38, [got_arg] (const rpc::client_info& ci, int x) {
            (void)ci;            // loopback addr family is unspecified; just observe it exists
            *got_arg = x;
            return make_ready_future<int>(x + 1);
        });
        test_proto::client c(env.proto, {}, env.make_socket(), ipv4_addr());
        auto call = env.proto.make_client<int (int)>(38);
        BOOST_REQUIRE_EQUAL(call(c, 7).get(), 8);
        BOOST_REQUIRE_EQUAL(*got_arg, 7);
        c.stop().get();
    });
}

// Bigger stress test: several clients, many concurrent calls, large payloads,
// each response verified against a locally-computed checksum.
SEASTAR_TEST_CASE(test_stress_many_clients_large_data) {
    return with_env([] (rpc_env& env) {
        constexpr unsigned n_clients = 8;
        constexpr unsigned calls_per_client = 60;
        constexpr size_t payload_size = 64 * 1024;

        // Verb: fold the payload into a checksum mixed with `seed`, and also
        // echo the length back, so the client can validate both.
        env.register_handler(40, [] (uint64_t seed, sstring data) {
            uint64_t h = seed;
            for (unsigned char ch : data) {
                h = h * 1099511628211ull + ch;   // FNV-ish mix
            }
            return make_ready_future<rpc::tuple<uint64_t, uint64_t>>(
                rpc::tuple<uint64_t, uint64_t>(h, data.size()));
        });

        auto checksum = [] (uint64_t seed, const sstring& data) {
            uint64_t h = seed;
            for (unsigned char ch : data) {
                h = h * 1099511628211ull + ch;
            }
            return h;
        };

        // Spin up the clients.
        std::vector<std::unique_ptr<test_proto::client>> clients;
        for (unsigned i = 0; i < n_clients; ++i) {
            clients.push_back(std::make_unique<test_proto::client>(
                env.proto, rpc::client_options{}, env.make_socket(), ipv4_addr()));
        }

        auto call = env.proto.make_client<rpc::tuple<uint64_t, uint64_t> (uint64_t, sstring)>(40);
        auto total_ok = make_lw_shared<uint64_t>(0);

        // Each client fires `calls_per_client` calls concurrently; all clients
        // run in parallel.
        parallel_for_each(std::views::iota(0u, n_clients), [&] (unsigned ci) {
            return parallel_for_each(std::views::iota(0u, calls_per_client), [&, ci] (unsigned k) {
                uint64_t seed = (uint64_t(ci) << 32) | k;
                // Distinct, non-trivial payload per (client, call).
                sstring payload(payload_size, char('A' + ((ci + k) % 26)));
                for (size_t p = 0; p < payload.size(); p += 997) {
                    payload[p] = char('0' + (p % 10));
                }
                uint64_t expected = checksum(seed, payload);
                return call(*clients[ci], seed, std::move(payload)).then(
                        [expected, total_ok] (rpc::tuple<uint64_t, uint64_t> r) {
                    auto [h, len] = r;
                    BOOST_REQUIRE_EQUAL(h, expected);
                    BOOST_REQUIRE_EQUAL(len, uint64_t(64 * 1024));
                    ++*total_ok;
                });
            });
        }).get();

        BOOST_REQUIRE_EQUAL(*total_ok, uint64_t(n_clients) * calls_per_client);

        for (auto& c : clients) {
            c->stop().get();
        }
    });
}
