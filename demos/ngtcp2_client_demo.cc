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

#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

#include <seastar/core/app-template.hh>
#include <seastar/core/coroutine.hh>
#include <seastar/core/reactor.hh>
#include <seastar/core/sleep.hh>
#include <seastar/core/temporary_buffer.hh>
#include <seastar/core/when_all.hh>
#include <seastar/quic/quic_client.hh>

#include "../apps/lib/stop_signal.hh"

using namespace seastar;
using namespace seastar::quic::experimental;
namespace bpo = boost::program_options;

static socket_address parse_ipv6_address(const std::string& ip, uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip.c_str(), &sa.sin6_addr) != 1) {
        throw std::runtime_error("Invalid IPv6 address: " + ip);
    }
    return socket_address(sa);
}

class stdin_flag_guard {
public:
    explicit stdin_flag_guard(int fd)
        : _fd(fd)
        , _old_flags(fcntl(fd, F_GETFL, 0)) {
        if (_old_flags < 0) {
            throw std::runtime_error("fcntl(F_GETFL) failed");
        }
        if (fcntl(_fd, F_SETFL, _old_flags | O_NONBLOCK) < 0) {
            throw std::runtime_error("fcntl(F_SETFL) failed");
        }
        _active = true;
    }

    ~stdin_flag_guard() {
        if (_active) {
            (void)fcntl(_fd, F_SETFL, _old_flags);
        }
    }

    stdin_flag_guard(const stdin_flag_guard&) = delete;
    stdin_flag_guard& operator=(const stdin_flag_guard&) = delete;

private:
    int _fd;
    int _old_flags = 0;
    bool _active = false;
};

static future<> receive_loop(lw_shared_ptr<connection> session) {
    while (session->is_open()) {
        try {
            auto msg = co_await session->receive();
            std::cout.write(msg.payload.get(), static_cast<std::streamsize>(msg.payload.size()));
            if (msg.payload.size() && msg.payload.get()[msg.payload.size() - 1] != '\n') {
                std::cout << "\n";
            }
            std::cout.flush();
        } catch (const quic_exception& e) {
            if (e.code() == quic_error::closed) {
                co_return;
            }
            throw;
        }
    }
}

static future<> input_loop(lw_shared_ptr<connection> session, std::chrono::milliseconds poll_interval, bool verbose) {
    char buf[2048];
    while (session->is_open()) {
        auto n = ::read(STDIN_FILENO, buf, sizeof(buf));
        if (n > 0) {
            temporary_buffer<char> tb(static_cast<size_t>(n));
            std::memcpy(tb.get_write(), buf, static_cast<size_t>(n));
            if (verbose) {
                std::cout << "[client] send bytes=" << n << "\n";
                std::cout.flush();
            }
            co_await session->send(invalid_stream_id, std::move(tb));
            continue;
        }
        if (n == 0) {
            co_await session->close();
            co_return;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            co_await sleep(poll_interval);
            continue;
        }

        throw std::runtime_error(std::string("stdin read failed: ") + std::strerror(errno));
    }
}

int main(int argc, char** argv) {
    app_template app;
    app.add_options()
      ("address", bpo::value<std::string>()->default_value("::1"), "Server IPv6 address")
      ("port", bpo::value<uint16_t>()->default_value(4444), "Server UDP port")
      ("server-name", bpo::value<std::string>()->default_value("localhost"), "TLS server name (SNI)")
      ("stdin-poll-ms", bpo::value<unsigned>()->default_value(50), "Polling interval for stdin in milliseconds")
      ("verbose,v", bpo::value<bool>()->default_value(false)->implicit_value(true), "Verbose logging");

    return app.run(argc, argv, [&app]() -> future<int> {
        quic_client client;
        lw_shared_ptr<connection> session;
        std::exception_ptr error;

        try {
            auto&& cfg = app.configuration();
            auto address = cfg["address"].as<std::string>();
            auto port = cfg["port"].as<uint16_t>();
            auto server_name = cfg["server-name"].as<std::string>();
            auto poll_ms = cfg["stdin-poll-ms"].as<unsigned>();
            auto verbose = cfg["verbose"].as<bool>();

            quic_client_config client_cfg;
            client_cfg.remote_address = parse_ipv6_address(address, port);
            client_cfg.server_name = server_name;

            session = make_lw_shared<connection>(co_await client.connect(std::move(client_cfg)));
            stdin_flag_guard guard(STDIN_FILENO);

            if (verbose) {
                std::cout << "[client] connected to [" << address << "]:" << port << "\n";
                std::cout.flush();
            }

            seastar_apps_lib::stop_signal stop_signal;
            auto stop_task = stop_signal.wait().then([session]() {
                if (session && session->is_open()) {
                    std::cout << "[client] SIGINT received, closing session...\n";
                    std::cout.flush();
                    return session->close();
                }
                return make_ready_future<>();
            }).handle_exception([](std::exception_ptr) {});

            co_await when_all_succeed(
                       receive_loop(session),
                       input_loop(session, std::chrono::milliseconds(poll_ms), verbose))
              .discard_result();
        } catch (...) {
            error = std::current_exception();
        }

        if (session) {
            try {
                co_await session->close();
            } catch (...) {
            }
        }

        try {
            co_await client.stop();
        } catch (...) {
        }

        if (error) {
            try {
                std::rethrow_exception(error);
            } catch (const std::exception& e) {
                std::cerr << "[client] fatal: " << e.what() << "\n";
            } catch (...) {
                std::cerr << "[client] fatal: unknown exception\n";
            }
            co_return 1;
        }
        co_return 0;
    });
}
