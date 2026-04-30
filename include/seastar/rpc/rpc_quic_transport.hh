/*
 * This file is open source software, licensed to you under the terms
 * of the Apache License, Version 2.0 (the "License").  See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership.  You may obtain a copy of the License at
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

#pragma once

#include <seastar/quic/quic.hh>
#include <seastar/rpc/rpc.hh>

namespace seastar::rpc::experimental {

class quic_client_transport final : public connection::transport {
public:
    quic_client_transport(
            seastar::quic::experimental::connection conn,
            seastar::quic::experimental::stream control_stream);

    input_stream<char>& input() override;
    output_stream<char>& output() override;
    void shutdown_input() override;
    void shutdown_output() override;
    future<internal::incoming_request> receive_request(connection& owner) override;
    future<> send_request(connection& owner, snd_buf&& data, std::optional<rpc_clock_type::time_point> timeout, cancellable* cancel) override;

private:
    seastar::quic::experimental::connection _conn;
    seastar::quic::experimental::stream _control_stream;
    input_stream<char> _control_input;
    output_stream<char> _control_output;
    gate _response_gate;
};

class quic_server_transport final : public connection::transport {
public:
    quic_server_transport(
            seastar::quic::experimental::connection conn,
            seastar::quic::experimental::stream control_stream);

    input_stream<char>& input() override;
    output_stream<char>& output() override;
    void shutdown_input() override;
    void shutdown_output() override;
    future<internal::incoming_request> receive_request(connection& owner) override;
    future<> send_request(connection& owner, snd_buf&& data, std::optional<rpc_clock_type::time_point> timeout, cancellable* cancel) override;

private:
    seastar::quic::experimental::connection _conn;
    seastar::quic::experimental::stream _control_stream;
    input_stream<char> _control_input;
    output_stream<char> _control_output;
};

} // namespace seastar::rpc::experimental
