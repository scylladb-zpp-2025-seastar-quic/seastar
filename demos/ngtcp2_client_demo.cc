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
#include <seastar/quic/quic_error.hh>

static constexpr const char* SERVER_HOST = "localhost";
static constexpr const char* SERVER_IP   = "::1";
static constexpr uint16_t    SERVER_PORT = 4444;
static constexpr size_t      MAX_UDP_OUT = 65536;

static seastar::logger qlog("quic-client");

using udp_channel_ptr = seastar::quic::experimental::udp_channel_ptr;


struct conn_data : public seastar::quic::experimental::Connection {
    bool closing = false;
    bool handshake_done = false;

    int64_t stream_id = -1;
    bool stream_opened = false;
};

using conn_data_ptr = seastar::lw_shared_ptr<conn_data>;

static seastar::quic::experimental::QuicConfig create_config(const conn_data_ptr& c) {
    seastar::quic::experimental::QuicConfig conf;
    c->on_handshake_completed([c](seastar::quic::experimental::Connection&) {
        c->handshake_done = true;
        qlog.info("Handshake completed. Write text and press ENTER:");
    });
    c->on_stream_data([](seastar::quic::experimental::Connection&, int64_t, std::string_view data) {
        fmt::print("[Server]: {:.{}}", data.data(), data.size());
    });
    c->apply_default_callbacks(conf);

    return conf;
}

seastar::future<> send_connection_close(conn_data_ptr c, udp_channel_ptr sock) {
    if (!c || !sock || !c->conn()) co_return;

    std::vector<uint8_t> outbuf(c->max_tx_udp_payload_size());

    ssize_t nwrite = c->write_connection_close(outbuf.data(), outbuf.size());

    if (nwrite > 0) {
        auto tb = seastar::temporary_buffer<char>((size_t)nwrite);
        std::memcpy(tb.get_write(), outbuf.data(), (size_t)nwrite);
        co_await sock->send_to(c->peer(), std::move(tb));
        qlog.info("Sending CONNECTION_CLOSE.");
    }
}

seastar::future<> net_loop(conn_data_ptr c, udp_channel_ptr sock) {
    try {
        while (!c->closing) {
            auto d = co_await sock->recv_datagram();
            auto tb = seastar::quic::experimental::datagram_to_temporary_buffer(d);

            int rv = co_await c->handle_packet((const uint8_t*)tb.get(), tb.size(), sock);
            if (rv < 0) {
                qlog.error("QUIC receive error");
                c->closing = true;
                break;
            }
        }
    } catch (const seastar::broken_promise& e) {
        qlog.debug("Net loop: connection closed.");
    } catch (const std::exception& e) {
        qlog.error("Net loop: unexpected error: {}", e.what());
    }
}

seastar::future<> input_loop(conn_data_ptr c, udp_channel_ptr sock) {
    // Setting stdin as nonblocking.
    int flags = fcntl(0, F_GETFL, 0);
    fcntl(0, F_SETFL, flags | O_NONBLOCK);
    char buf[1024];

    while (!c->closing) {
        ssize_t n = read(0, buf, sizeof(buf));
        if (n > 0) {
            co_await c->send(c->stream_id, std::string_view(buf, n), sock, c->peer());
        } 
        else if (n == 0) {
            co_await send_connection_close(c, sock);
            c->closing = true;
            c->reschedule();
            sock->close();
            break;
        } 
        else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                co_await seastar::sleep(std::chrono::milliseconds(50));
            } else {
                qlog.error("stdin error: {}", strerror(errno));
                c->closing = true;
                c->reschedule();
                sock->close();
                break;
            }
        }
    }
}

seastar::future<> connection_timer_loop(conn_data_ptr c, udp_channel_ptr sock) {
    while (!c->closing) {
        auto now = seastar::quic::experimental::now_ns();
        auto expiry = c->get_expiry();

        try {
            if (expiry == UINT64_MAX) {
                co_await c->timer_cv().wait();
            } 
            else if (expiry > now) {
                co_await c->timer_cv().wait(std::chrono::nanoseconds(expiry - now));
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
                sock->close();
                break;
            }
        }

        co_await c->flush_pending(sock, c->peer());
    }
}

int main(int argc, char** argv) {
    std::srand((unsigned)time(nullptr));

    seastar::quic::experimental::init_gnutls gnutls;

    seastar::app_template app;
    int rc = app.run(argc, argv, []() -> seastar::future<int> {
        try {
            seastar_apps_lib::stop_signal stop_signal;
            auto c = seastar::make_lw_shared<conn_data>(); 

            auto crypto = seastar::make_lw_shared<seastar::quic::experimental::client::client_crypto_config>
                                                (std::vector<std::string>{"h3"});
            auto sock = co_await seastar::quic::experimental::client::setup_quic_client(
                *c, SERVER_HOST, SERVER_IP, SERVER_PORT, create_config(c), crypto);
            
            auto net_fut = net_loop(c, sock);
            auto in_fut  = input_loop(c, sock);
            auto tim_fut = connection_timer_loop(c, sock);

            // Waiting for ctrl+c signal.
            auto stop_handler = stop_signal.wait().then([c, sock]() {
                if (!c->closing) {
                    qlog.info("SIGINT received");
                    c->closing = true;
                    sock->close();
                    c->reschedule();
                }
            }).handle_exception([](std::exception_ptr) {});

            co_await seastar::when_all_succeed(std::move(net_fut), std::move(in_fut), std::move(tim_fut));

            if (!c->closing) {
                c->closing = true;
            }

            sock->close();
            c->reschedule();

            co_return 0;

        } catch (const std::exception& e) {
            qlog.error("fatal: {}", e.what());
            co_return 1;
        }
    });

    return rc;
}
