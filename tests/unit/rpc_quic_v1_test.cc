/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
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

#include <seastar/core/abort_source.hh>
#include <seastar/core/condition-variable.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/future.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/thread.hh>
#include <seastar/net/api.hh>
#include <seastar/quic/quic.hh>
#include <seastar/quic/quic_client.hh>
#include <seastar/quic/quic_server.hh>
#include <seastar/rpc/lz4_compressor.hh>
#include <seastar/rpc/multi_algo_compressor_factory.hh>
#include <seastar/rpc/rpc.hh>
#include <seastar/rpc/rpc_quic_adapters.hh>
#include <seastar/rpc/rpc_types.hh>
#include <seastar/testing/test_case.hh>
#include <seastar/util/closeable.hh>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <exception>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

using namespace seastar;

namespace {

struct serializer {
};

template <typename T, typename Output>
void write_arithmetic_type(Output& out, T v) {
    static_assert(std::is_arithmetic_v<T>, "must be arithmetic type");
    out.write(reinterpret_cast<const char*>(&v), sizeof(T));
}

template <typename T, typename Input>
T read_arithmetic_type(Input& in) {
    static_assert(std::is_arithmetic_v<T>, "must be arithmetic type");
    T v;
    in.read(reinterpret_cast<char*>(&v), sizeof(T));
    return v;
}

template <typename Output>
void write(serializer, Output& output, int32_t v) { write_arithmetic_type(output, v); }
template <typename Output>
void write(serializer, Output& output, uint32_t v) { write_arithmetic_type(output, v); }
template <typename Output>
void write(serializer, Output& output, int64_t v) { write_arithmetic_type(output, v); }
template <typename Output>
void write(serializer, Output& output, uint64_t v) { write_arithmetic_type(output, v); }
template <typename Output>
void write(serializer, Output& output, double v) { write_arithmetic_type(output, v); }
template <typename Input>
int32_t read(serializer, Input& input, rpc::type<int32_t>) { return read_arithmetic_type<int32_t>(input); }
template <typename Input>
uint32_t read(serializer, Input& input, rpc::type<uint32_t>) { return read_arithmetic_type<uint32_t>(input); }
template <typename Input>
uint64_t read(serializer, Input& input, rpc::type<uint64_t>) { return read_arithmetic_type<uint64_t>(input); }
template <typename Input>
int64_t read(serializer, Input& input, rpc::type<int64_t>) { return read_arithmetic_type<int64_t>(input); }
template <typename Input>
double read(serializer, Input& input, rpc::type<double>) { return read_arithmetic_type<double>(input); }

template <typename Output>
void write(serializer, Output& out, const sstring& v) {
    write_arithmetic_type(out, uint32_t(v.size()));
    out.write(v.c_str(), v.size());
}

template <typename Input>
sstring read(serializer, Input& in, rpc::type<sstring>) {
    auto size = read_arithmetic_type<uint32_t>(in);
    auto ret = uninitialized_string(size);
    in.read(ret.data(), size);
    return ret;
}

using test_rpc_proto = rpc::protocol<serializer>;

socket_address allocate_loopback_quic_address() {
    auto probe = make_bound_datagram_channel(make_ipv4_address({0x7f000001, 0}));
    auto address = probe.local_address();
    probe.close();
    return address;
}

quic::experimental::connection_options rpc_quic_options() {
    quic::experimental::connection_options opts;
    opts.transport.initial_max_stream_data_bidi_local = 4 * 1024 * 1024;
    opts.transport.initial_max_stream_data_bidi_remote = 4 * 1024 * 1024;
    opts.transport.initial_max_data = 64 * 1024 * 1024;
    return opts;
}

quic::experimental::quic_server_config rpc_quic_server_config(socket_address address) {
    quic::experimental::quic_server_config server_cfg;
    server_cfg.listen_address = address;
    server_cfg.crt_file = "test.crt";
    server_cfg.key_file = "test.key";
    server_cfg.alpns = {sstring("seastar-rpc")};
    server_cfg.session_options = rpc_quic_options();
    return server_cfg;
}

quic::experimental::quic_client_config rpc_quic_client_config(socket_address address) {
    quic::experimental::quic_client_config client_cfg;
    client_cfg.remote_address = address;
    client_cfg.server_name = "test.scylladb.org";
    client_cfg.ca_file = "test.crt";
    client_cfg.alpns = {sstring("seastar-rpc")};
    client_cfg.session_options = rpc_quic_options();
    return client_cfg;
}

struct rpc_quic_test_config {
    rpc::resource_limits resource_limits = {};
    rpc::server_options server_options = {};
    rpc::client_options client_options = {};
};

class rpc_quic_test_env {
    rpc_quic_test_config _cfg;
    socket_address _address;
    test_rpc_proto _proto;
    std::optional<test_rpc_proto::server> _server;
    std::vector<int> _handlers;

public:
    explicit rpc_quic_test_env(rpc_quic_test_config cfg)
        : _cfg(std::move(cfg))
        , _address(allocate_loopback_quic_address())
        , _proto(serializer{}) {
        auto server_cfg = rpc_quic_server_config(_address);
        auto ss = rpc::experimental::make_quic_server_socket(std::move(server_cfg));
        _server.emplace(_proto, _cfg.server_options, std::move(ss), _cfg.resource_limits);
    }

    test_rpc_proto& proto() {
        return _proto;
    }

    test_rpc_proto::server& server() {
        return *_server;
    }

    socket_address address() const {
        return _address;
    }

    test_rpc_proto::client make_client() {
        return test_rpc_proto::client(_proto, _cfg.client_options, make_socket(), _address);
    }

    seastar::socket make_socket() {
        auto client_cfg = rpc_quic_client_config(_address);
        return rpc::experimental::make_quic_client_socket(std::move(client_cfg));
    }

    template <typename Func>
    auto register_handler(int verb, Func&& func) {
        _handlers.push_back(verb);
        return _proto.register_handler(verb, std::forward<Func>(func));
    }

    future<> stop() {
        return parallel_for_each(_handlers, [this] (int verb) {
            return _proto.unregister_handler(verb);
        }).then([this] {
            return _server->stop();
        });
    }

    template <typename Func>
    static future<> do_with_thread(rpc_quic_test_config cfg, Func&& func) {
        return seastar::async([cfg = std::move(cfg), func = std::forward<Func>(func)] () mutable {
            rpc_quic_test_env env(std::move(cfg));
            std::exception_ptr error;
            try {
                func(env);
            } catch (...) {
                error = std::current_exception();
            }
            try {
                env.stop().get();
                sleep(std::chrono::milliseconds(10)).get();
            } catch (...) {
                if (!error) {
                    error = std::current_exception();
                }
            }
            if (error) {
                std::rethrow_exception(error);
            }
        });
    }
};

struct cfactory : rpc::compressor::factory {
    mutable int use_compression = 0;
    const sstring name;

    explicit cfactory(sstring name_ = "LZ4")
        : name(std::move(name_)) {
    }

    const sstring& supported() const override {
        return name;
    }

    class mylz4 : public rpc::lz4_compressor {
        sstring _name;
    public:
        explicit mylz4(const sstring& n) : _name(n) {
        }
        sstring name() const override {
            return _name;
        }
    };

    std::unique_ptr<rpc::compressor> negotiate(sstring feature, bool is_server) const override {
        if (feature == name) {
            ++use_compression;
            return std::make_unique<mylz4>(name);
        }
        return nullptr;
    }
};


void run_stream_roundtrip(rpc_quic_test_env& env, test_rpc_proto::client& cl, int verb) {
    bool client_source_closed = false;
    bool server_source_closed = false;
    int server_sum = 0;
    future<> server_done = make_ready_future<>();

    env.register_handler(verb, [&] (int marker, rpc::source<int> source) {
        BOOST_REQUIRE_EQUAL(marker, 666);
        auto sink = source.make_sink<serializer, sstring>();

        auto sink_loop = seastar::async([sink] () mutable {
            for (auto i = 0; i < 10; ++i) {
                sink("seastar").get();
                sleep(std::chrono::milliseconds(1)).get();
            }
            sink.flush().get();
            sink.close().get();
        });

        auto source_loop = seastar::async([source, &server_source_closed, &server_sum] () mutable {
            try {
                while (!server_source_closed) {
                    auto data = source().get();
                    if (data) {
                        server_sum += std::get<0>(*data);
                    } else {
                        server_source_closed = true;
                        BOOST_REQUIRE_THROW(source().get(), rpc::stream_closed);
                    }
                }
            } catch (const rpc::stream_closed&) {
                server_source_closed = true;
            }
        });

        server_done = when_all_succeed(std::move(sink_loop), std::move(source_loop)).discard_result();
        return sink;
    });

    auto sink = cl.make_stream_sink<serializer, int>(env.make_socket()).get();
    auto call = env.proto().make_client<rpc::source<sstring> (int, rpc::sink<int>)>(verb);
    auto source = call(cl, 666, sink).get();

    auto source_done = seastar::async([source, &client_source_closed] () mutable {
        int received = 0;
        try {
            while (!client_source_closed) {
                auto data = source().get();
                if (data) {
                    BOOST_REQUIRE_EQUAL(std::get<0>(*data), "seastar");
                    ++received;
                } else {
                    client_source_closed = true;
                }
            }
        } catch (const rpc::stream_closed&) {
            client_source_closed = true;
        }
        BOOST_REQUIRE_EQUAL(received, 10);
    });

    auto sink_done = seastar::async([sink] () mutable {
        for (auto i = 1; i <= 10; ++i) {
            sink(i).get();
            sleep(std::chrono::milliseconds(1)).get();
        }
        sink.flush().get();
        sink.close().get();
    });

    sink_done.get();
    source_done.get();
    server_done.get();

    BOOST_REQUIRE(client_source_closed);
    BOOST_REQUIRE(server_source_closed);
    BOOST_REQUIRE_EQUAL(server_sum, 55);
}


template <typename Func>
void with_active_stream(rpc_quic_test_env& env, test_rpc_proto::client& cl, int verb, std::vector<int> values, int expected_sum, Func&& func) {
    promise<> stream_handler_started;
    auto stream_handler_started_f = stream_handler_started.get_future();
    int server_sum = 0;
    future<> server_done = make_ready_future<>();
    auto allow_server_close = std::make_shared<promise<>>();

    env.register_handler(verb, [&] (int marker, rpc::source<int> source) {
        BOOST_REQUIRE_EQUAL(marker, 666);
        auto sink = source.make_sink<serializer, sstring>();
        auto close_allowed = allow_server_close->get_future();
        stream_handler_started.set_value();

        server_done = seastar::async([source, sink, &server_sum, close_allowed = std::move(close_allowed)] () mutable {
            bool closed = false;
            try {
                while (!closed) {
                    auto data = source().get();
                    if (data) {
                        server_sum += std::get<0>(*data);
                    } else {
                        closed = true;
                    }
                }
            } catch (const rpc::stream_closed&) {
                closed = true;
            }
            sink("done").get();
            sink.flush().get();
            close_allowed.get();
            sink.close().get();
        });
        return sink;
    });

    auto sink = cl.make_stream_sink<serializer, int>(env.make_socket()).get();
    auto stream_call = env.proto().make_client<rpc::source<sstring> (int, rpc::sink<int>)>(verb);
    auto source = stream_call(cl, 666, sink).get();
    stream_handler_started_f.get();

    bool close_released = false;
    auto release_close = [&] {
        if (!close_released) {
            close_released = true;
            allow_server_close->set_value();
        }
    };

    try {
        func();
        for (auto value : values) {
            sink(value).get();
        }
        sink.flush().get();
        sink.close().get();

        auto result = source().get();
        BOOST_REQUIRE(result);
        BOOST_REQUIRE_EQUAL(std::get<0>(*result), "done");
        release_close();
        try {
            auto eof = source().get();
            BOOST_REQUIRE(!eof);
        } catch (const rpc::stream_closed&) {
        }
        server_done.get();
        BOOST_REQUIRE_EQUAL(server_sum, expected_sum);
    } catch (...) {
        release_close();
        throw;
    }
}

} // namespace

SEASTAR_TEST_CASE(test_rpc_quic_v1_stop_without_client) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env&) {
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_stop_after_accept_starts_without_client) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env&) {
        sleep(std::chrono::milliseconds(10)).get();
    });
}


SEASTAR_TEST_CASE(test_rpc_quic_v1_client_connects_are_not_pooled) {
    return seastar::async([] {
        auto address = allocate_loopback_quic_address();
        auto server_cfg = rpc_quic_server_config(address);
        auto ss = rpc::experimental::make_quic_server_socket(std::move(server_cfg));

        auto s1 = rpc::experimental::make_quic_client_socket(rpc_quic_client_config(address));
        auto s2 = rpc::experimental::make_quic_client_socket(rpc_quic_client_config(address));

        auto c1f = s1.connect(address);
        auto a1f = ss.accept();
        auto c1 = c1f.get();
        auto c1_out = c1.output();
        c1_out.write("x").get();
        c1_out.flush().get();
        auto a1 = a1f.get();

        auto c2f = s2.connect(address);
        auto a2f = ss.accept();
        auto c2 = c2f.get();
        auto c2_out = c2.output();
        c2_out.write("y").get();
        c2_out.flush().get();
        auto a2 = a2f.get();

        BOOST_REQUIRE(c1.local_address() != c2.local_address());
        BOOST_REQUIRE(a1.remote_address != a2.remote_address);

        c1_out.close().get();
        c2_out.close().get();
        c1.shutdown_input();
        c1.shutdown_output();
        c2.shutdown_input();
        c2.shutdown_output();
        a1.connection.shutdown_input();
        a1.connection.shutdown_output();
        a2.connection.shutdown_input();
        a2.connection.shutdown_output();
        s1.shutdown();
        s2.shutdown();
        ss.abort_accept();
        sleep(std::chrono::milliseconds(100)).get();
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_server_accepts_one_stream_per_quic_connection) {
    return seastar::async([] {
        auto address = allocate_loopback_quic_address();
        auto server_cfg = rpc_quic_server_config(address);
        auto ss = rpc::experimental::make_quic_server_socket(std::move(server_cfg));

        auto first_accept_f = ss.accept();

        quic::experimental::quic_client client;
        auto conn = client.connect(rpc_quic_client_config(address)).get();

        auto first_stream = conn.open_stream().get();
        auto first_socket = quic::experimental::to_connected_socket(std::move(first_stream));
        auto first_out = first_socket.output();
        first_out.write("x").get();
        first_out.flush().get();

        auto first_accept = first_accept_f.get();

        auto second_stream = conn.open_stream().then_wrapped([] (future<quic::experimental::stream> f) {
            f.ignore_ready_future();
        });
        auto second_accept = ss.accept().then_wrapped([] (future<accept_result> f) {
            f.ignore_ready_future();
        });
        sleep(std::chrono::milliseconds(20)).get();
        BOOST_REQUIRE(!second_stream.available());
        BOOST_REQUIRE(!second_accept.available());

        first_out.close().get();
        first_socket.shutdown_input();
        first_socket.shutdown_output();
        first_accept.connection.shutdown_input();
        first_accept.connection.shutdown_output();
        ss.abort_accept();
        conn.close().get();
        client.stop().get();
        second_stream.get();
        second_accept.get();
        sleep(std::chrono::milliseconds(100)).get();
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_connect) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);

        BOOST_REQUIRE_EQUAL(sum(cl, 2, 3).get(), 5);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_large_payload) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (sstring payload) {
            return make_ready_future<uint32_t>(payload.size());
        });
        auto size = env.proto().make_client<uint32_t (sstring)>(1);

        auto payload = uninitialized_string(128 * 1024);
        std::fill(payload.begin(), payload.end(), 'x');

        BOOST_REQUIRE_EQUAL(size(cl, std::move(payload)).get(), 128 * 1024);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_large_response) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (uint32_t size) {
            auto payload = uninitialized_string(size);
            std::fill(payload.begin(), payload.end(), 'r');
            return make_ready_future<sstring>(std::move(payload));
        });
        auto make_payload = env.proto().make_client<sstring (uint32_t)>(1);

        auto response = make_payload(cl, 128 * 1024).get();
        BOOST_REQUIRE_EQUAL(response.size(), 128 * 1024);
        BOOST_REQUIRE(std::all_of(response.begin(), response.end(), [] (char c) {
            return c == 'r';
        }));
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_pipelined_requests) {
    using namespace std::chrono_literals;

    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int v) {
            return sleep(std::chrono::milliseconds(30 - v * 10)).then([v] {
                return v * 10;
            });
        });
        auto call = env.proto().make_client<int (int)>(1);

        auto f1 = call(cl, 1);
        auto f2 = call(cl, 2);
        auto f3 = call(cl, 3);

        BOOST_REQUIRE_EQUAL(f1.get(), 10);
        BOOST_REQUIRE_EQUAL(f2.get(), 20);
        BOOST_REQUIRE_EQUAL(f3.get(), 30);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_cancel) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);
        bool rpc_executed = false;
        int good = 0;
        promise<> handler_called;
        auto f_handler_called = handler_called.get_future();

        env.register_handler(1, [&rpc_executed, &handler_called] {
            handler_called.set_value();
            rpc_executed = true;
            return sleep(std::chrono::milliseconds(1));
        });

        auto call = env.proto().make_client<void ()>(1);
        promise<> cont;
        rpc::cancellable cancel;
        cl.suspend_for_testing(cont);
        auto f = call(cl, cancel);

        cancel.cancel();
        cont.set_value();
        try {
            f.get();
        } catch (rpc::canceled_error&) {
            good += !rpc_executed;
        }

        f = call(cl, cancel);
        f_handler_called.then([&cancel] {
            cancel.cancel();
        }).get();
        try {
            f.get();
        } catch (rpc::canceled_error&) {
            good += 10 * rpc_executed;
        }

        BOOST_REQUIRE_EQUAL(good, 11);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_unknown_verb_after_unregister) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] {
            return make_ready_future<>();
        });
        auto call = env.proto().make_client<void ()>(1);
        call(cl).get();

        env.proto().unregister_handler(1).get();
        BOOST_REQUIRE_THROW(call(cl).get(), rpc::unknown_verb_error);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_unregister_handler_waits_for_inflight_call) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);
        promise<> handler_reached_promise;
        promise<> handler_go_promise;
        sstring value_to_return = "before_unregister";

        env.register_handler(1, [&] () -> future<sstring> {
            handler_reached_promise.set_value();
            return handler_go_promise.get_future().then([&] {
                return value_to_return;
            });
        });

        auto call = env.proto().make_client<future<sstring> ()>(1);
        auto response_future = call(cl);
        handler_reached_promise.get_future().get();

        auto unregister_future = env.proto().unregister_handler(1).then([&] {
            value_to_return = "after_unregister";
        });
        BOOST_REQUIRE(!unregister_future.available());
        sleep(std::chrono::milliseconds(1)).get();
        BOOST_REQUIRE(!unregister_future.available());

        handler_go_promise.set_value();
        unregister_future.get();
        BOOST_REQUIRE_EQUAL(response_future.get(), "before_unregister");
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_max_absolute_timeout) {
    rpc_quic_test_config cfg;
    cfg.client_options.send_timeout_data = true;

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);

        auto result = sum(cl, rpc::rpc_clock_type::time_point::max(), 2, 3).get();
        BOOST_REQUIRE_EQUAL(result, 5);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_max_relative_timeout) {
    rpc_quic_test_config cfg;
    cfg.client_options.send_timeout_data = true;

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);

        auto result = sum(cl, rpc::rpc_clock_type::duration::max(), 2, 3).get();
        BOOST_REQUIRE_EQUAL(result, 5);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_timeout_cancel) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);
        abort_source abort_handler;
        uint32_t id = 1;
        int sent = 0;
        int received = 0;
        int active = 0;
        condition_variable cond;
        condition_variable done;

        env.register_handler(id, [&] (int x) -> future<int> {
            ++active;
            received = x;
            cond.signal();
            try {
                co_await sleep_abortable(std::chrono::seconds(10), abort_handler);
            } catch (const sleep_aborted&) {
            }
            --active;
            done.broadcast();
            co_return x;
        });

        auto wait_until_received = [&] (int expected) {
            while (received != expected) {
                cond.wait(std::chrono::seconds(1)).get();
            }
        };
        auto wait_until_handlers_done = [&] {
            while (active != 0) {
                done.wait(std::chrono::seconds(1)).get();
            }
        };

        auto echo = env.proto().make_client<int (int)>(id);
        {
            auto f = echo(cl, std::chrono::milliseconds(200), ++sent);
            wait_until_received(sent);
            BOOST_REQUIRE_THROW(f.get(), rpc::timeout_error);
        }
        {
            auto f = echo(cl, rpc::rpc_clock_type::now() + std::chrono::milliseconds(200), ++sent);
            wait_until_received(sent);
            BOOST_REQUIRE_THROW(f.get(), rpc::timeout_error);
        }
        {
            rpc::cancellable cancel_rpc;
            auto f = echo(cl, std::chrono::seconds(5), cancel_rpc, ++sent);
            BOOST_REQUIRE(!f.available());
            wait_until_received(sent);
            cancel_rpc.cancel();
            BOOST_REQUIRE_THROW(f.get(), rpc::canceled_error);
        }
        {
            rpc::cancellable cancel_rpc;
            auto f = echo(cl, rpc::rpc_clock_type::now() + std::chrono::seconds(5), cancel_rpc, ++sent);
            BOOST_REQUIRE(!f.available());
            wait_until_received(sent);
            cancel_rpc.cancel();
            BOOST_REQUIRE_THROW(f.get(), rpc::canceled_error);
        }

        abort_handler.request_abort();
        wait_until_handlers_done();
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_stream_simple) {
    rpc_quic_test_config cfg;
    cfg.server_options.streaming_domain = rpc::streaming_domain_type(1);

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        run_stream_roundtrip(env, cl, 1);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_call_then_stream) {
    rpc_quic_test_config cfg;
    cfg.server_options.streaming_domain = rpc::streaming_domain_type(1);

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);
        BOOST_REQUIRE_EQUAL(sum(cl, 2, 3).get(), 5);

        run_stream_roundtrip(env, cl, 2);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_stream_then_call) {
    rpc_quic_test_config cfg;
    cfg.server_options.streaming_domain = rpc::streaming_domain_type(1);

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        run_stream_roundtrip(env, cl, 2);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);
        BOOST_REQUIRE_EQUAL(sum(cl, 4, 6).get(), 10);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_request_while_stream_active) {
    rpc_quic_test_config cfg;
    cfg.server_options.streaming_domain = rpc::streaming_domain_type(1);

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);

        with_active_stream(env, cl, 2, std::vector<int>{7}, 7, [&] {
            BOOST_REQUIRE_EQUAL(sum(cl, 20, 22).get(), 42);
        });
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_rpc_errors_while_stream_active) {
    rpc_quic_test_config cfg;
    cfg.server_options.streaming_domain = rpc::streaming_domain_type(1);

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        with_active_stream(env, cl, 2, std::vector<int>{11, 22}, 33, [&] {
            auto unknown = env.proto().make_client<void ()>(100000000);
            BOOST_REQUIRE_THROW(unknown(cl).get(), rpc::unknown_verb_error);

            env.register_handler(1, [] {
                throw std::runtime_error("boom");
            });
            auto failing = env.proto().make_client<void ()>(1);
            BOOST_REQUIRE_THROW(failing(cl).get(), rpc::remote_verb_error);
        });
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_timeout_and_cancel_while_stream_active) {
    rpc_quic_test_config cfg;
    cfg.server_options.streaming_domain = rpc::streaming_domain_type(1);

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);
        abort_source abort_handler;
        int sent = 0;
        int received = 0;
        int active = 0;
        condition_variable cond;
        condition_variable done;

        env.register_handler(1, [&] (int value) -> future<int> {
            ++active;
            received = value;
            cond.signal();
            try {
                co_await sleep_abortable(std::chrono::seconds(10), abort_handler);
            } catch (const sleep_aborted&) {
            }
            --active;
            done.broadcast();
            co_return value;
        });
        auto wait_until_received = [&] (int expected) {
            while (received != expected) {
                cond.wait(std::chrono::seconds(1)).get();
            }
        };
        auto wait_until_handlers_done = [&] {
            while (active != 0) {
                done.wait(std::chrono::seconds(1)).get();
            }
        };

        with_active_stream(env, cl, 2, std::vector<int>{3, 4}, 7, [&] {
            auto slow = env.proto().make_client<int (int)>(1);
            {
                auto timed_out = slow(cl, std::chrono::milliseconds(200), ++sent);
                wait_until_received(sent);
                BOOST_REQUIRE_THROW(timed_out.get(), rpc::timeout_error);
            }
            {
                rpc::cancellable cancel_rpc;
                auto canceled = slow(cl, std::chrono::seconds(5), cancel_rpc, ++sent);
                BOOST_REQUIRE(!canceled.available());
                wait_until_received(sent);
                cancel_rpc.cancel();
                BOOST_REQUIRE_THROW(canceled.get(), rpc::canceled_error);
            }

            abort_handler.request_abort();
            wait_until_handlers_done();
        });
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_two_concurrent_streams) {
    rpc_quic_test_config cfg;
    cfg.server_options.streaming_domain = rpc::streaming_domain_type(1);

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);
        int server_sum1 = 0;
        int server_sum2 = 0;
        future<> server_done1 = make_ready_future<>();
        future<> server_done2 = make_ready_future<>();
        std::vector<std::shared_ptr<promise<>>> allow_server_close(3);

        env.register_handler(3, [&] (int marker, rpc::source<int> source) {
            BOOST_REQUIRE(marker == 1 || marker == 2);
            auto sink = source.make_sink<serializer, sstring>();
            auto reply = marker == 1 ? sstring("one") : sstring("two");
            auto close_allowed = allow_server_close[marker]->get_future();

            auto& server_done = marker == 1 ? server_done1 : server_done2;
            auto& server_sum = marker == 1 ? server_sum1 : server_sum2;
            server_done = seastar::async([source, sink, &server_sum, reply = std::move(reply), close_allowed = std::move(close_allowed)] () mutable {
                bool closed = false;
                try {
                    while (!closed) {
                        auto data = source().get();
                        if (data) {
                            server_sum += std::get<0>(*data);
                        } else {
                            closed = true;
                        }
                    }
                } catch (const rpc::stream_closed&) {
                    closed = true;
                }
                for (auto i = 0; i < 3; ++i) {
                    sink(reply).get();
                }
                sink.flush().get();
                close_allowed.get();
                sink.close().get();
            });
            return sink;
        });

        auto stream_call = env.proto().make_client<rpc::source<sstring> (int, rpc::sink<int>)>(3);
        auto check_source = [] (rpc::source<sstring> source, const sstring& expected, std::shared_ptr<promise<>> close_allowed) {
            bool close_released = false;
            auto release_close = [&] {
                if (!close_released) {
                    close_released = true;
                    close_allowed->set_value();
                }
            };
            int received = 0;
            try {
                while (received != 3) {
                    auto data = source().get();
                    BOOST_REQUIRE(data);
                    BOOST_REQUIRE_EQUAL(std::get<0>(*data), expected);
                    ++received;
                }
            } catch (...) {
                release_close();
                throw;
            }
            release_close();
            try {
                auto data = source().get();
                BOOST_REQUIRE(!data);
            } catch (const rpc::stream_closed&) {
            }
        };

        allow_server_close[1] = std::make_shared<promise<>>();
        allow_server_close[2] = std::make_shared<promise<>>();

        auto sink1 = cl.make_stream_sink<serializer, int>(env.make_socket()).get();
        auto source1 = stream_call(cl, 1, sink1).get();
        auto sink2 = cl.make_stream_sink<serializer, int>(env.make_socket()).get();
        auto source2 = stream_call(cl, 2, sink2).get();

        sink1(1).get();
        sink2(10).get();
        sink1(2).get();
        sink2(20).get();
        sink1.flush().get();
        sink2.flush().get();
        sink1.close().get();
        sink2.close().get();

        check_source(source1, "one", allow_server_close[1]);
        check_source(source2, "two", allow_server_close[2]);
        server_done1.get();
        server_done2.get();
        BOOST_REQUIRE_EQUAL(server_sum1, 3);
        BOOST_REQUIRE_EQUAL(server_sum2, 30);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_tuple) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] {
            return make_ready_future<rpc::tuple<int, int64_t>>(rpc::tuple<int, int64_t>(1, 0x7'0000'0000L));
        });
        auto call = env.proto().make_client<rpc::tuple<int, int64_t> ()>(1);
        auto result = call(cl).get();
        BOOST_REQUIRE_EQUAL(std::get<0>(result), 1);
        BOOST_REQUIRE_EQUAL(std::get<1>(result), 0x7'0000'0000L);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_nonvariadic_client_variadic_server) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] {
            return make_ready_future<rpc::tuple<int, int64_t>>(rpc::tuple(1, 0x7'0000'0000L));
        });
        auto call = env.proto().make_client<future<rpc::tuple<int, int64_t>> ()>(1);
        auto result = call(cl).get();
        BOOST_REQUIRE_EQUAL(std::get<0>(result), 1);
        BOOST_REQUIRE_EQUAL(std::get<1>(result), 0x7'0000'0000L);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_variadic_client_nonvariadic_server) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] {
            return make_ready_future<rpc::tuple<int, int64_t>>(rpc::tuple<int, int64_t>(1, 0x7'0000'0000L));
        });
        auto call = env.proto().make_client<future<rpc::tuple<int, int64_t>> ()>(1);
        auto result = call(cl).get();
        BOOST_REQUIRE_EQUAL(std::get<0>(result), 1);
        BOOST_REQUIRE_EQUAL(std::get<1>(result), 0x7'0000'0000L);
    });
}


SEASTAR_TEST_CASE(test_rpc_quic_v1_connect_with_compression) {
    auto factory = std::make_unique<cfactory>();

    rpc_quic_test_config cfg;
    cfg.server_options.compressor_factory = factory.get();
    cfg.client_options.compressor_factory = factory.get();

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);

        BOOST_REQUIRE_EQUAL(sum(cl, 2, 3).get(), 5);
    }).finally([factory = std::move(factory)] {
        BOOST_REQUIRE_EQUAL(factory->use_compression, 2);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_connect_multi_compression_algo) {
    auto factory1 = std::make_shared<cfactory>();
    auto factory2 = std::make_shared<cfactory>("LZ4NEW");
    auto server_factory = std::make_shared<rpc::multi_algo_compressor_factory>(
      std::vector<const rpc::compressor::factory*>{factory1.get(), factory2.get()});
    auto client_factory = std::make_shared<rpc::multi_algo_compressor_factory>(
      std::vector<const rpc::compressor::factory*>{factory2.get(), factory1.get()});

    rpc_quic_test_config cfg;
    cfg.server_options.compressor_factory = server_factory.get();
    cfg.client_options.compressor_factory = client_factory.get();

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [server_factory, client_factory] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] (int a, int b) {
            return make_ready_future<int>(a + b);
        });
        auto sum = env.proto().make_client<int (int, int)>(1);

        BOOST_REQUIRE_EQUAL(sum(cl, 2, 3).get(), 5);
    }).finally([factory1, factory2] {
        BOOST_REQUIRE_EQUAL(factory1->use_compression, 0);
        BOOST_REQUIRE_EQUAL(factory2->use_compression, 2);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_remote_verb_error) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] {
            throw std::runtime_error("error");
        });
        auto call = env.proto().make_client<void ()>(1);

        BOOST_REQUIRE_THROW(call(cl).get(), rpc::remote_verb_error);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_unknown_verb) {
    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        auto call = env.proto().make_client<void ()>(100000000);

        BOOST_REQUIRE_THROW(call(cl).get(), rpc::unknown_verb_error);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_message_too_big) {
    rpc_quic_test_config cfg;
    cfg.resource_limits = {0, 1, 100};

    return rpc_quic_test_env::do_with_thread(std::move(cfg), [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);
        bool handler_called = false;

        env.register_handler(1, [&handler_called] (sstring payload) {
            handler_called = true;
        });
        auto call = env.proto().make_client<void (sstring)>(1);

        BOOST_REQUIRE_THROW(call(cl, uninitialized_string(101)).get(), std::runtime_error);
        BOOST_REQUIRE(!handler_called);
    });
}

SEASTAR_TEST_CASE(test_rpc_quic_v1_timeout) {
    using namespace std::chrono_literals;

    return rpc_quic_test_env::do_with_thread({}, [] (rpc_quic_test_env& env) {
        auto cl = env.make_client();
        auto stop = deferred_stop(cl);

        env.register_handler(1, [] {
            return sleep(100ms);
        });
        auto call = env.proto().make_client<void ()>(1);

        BOOST_REQUIRE_THROW(call(cl, 1ms).get(), rpc::timeout_error);
    });
}
