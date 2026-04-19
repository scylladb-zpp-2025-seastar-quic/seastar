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

#pragma once

#include <seastar/net/api.hh>
#include <seastar/quic/quic_client.hh>
#include <seastar/quic/quic_server.hh>
#include <seastar/rpc/rpc.hh>

namespace seastar::rpc::experimental {

/// Returns a seastar socket that transports one RPC connection over QUIC.
/// The socket connects with QUIC, opens exactly one bidirectional stream, and
/// exposes that stream as the connected_socket used by the existing RPC layer.
socket make_quic_client_socket(quic::experimental::quic_client_config config);

/// Returns a server socket that accepts QUIC sessions and exposes exactly one
/// peer-initiated bidirectional stream per session as an RPC connected_socket.
server_socket make_quic_server_socket(quic::experimental::quic_server_config config);

template<typename Serializer, typename MsgType = uint32_t>
class quic_client : public rpc::protocol<Serializer, MsgType>::client {
    using protocol_type = rpc::protocol<Serializer, MsgType>;
    using base = typename protocol_type::client;

public:
    quic_client(protocol_type& proto, quic::experimental::quic_client_config config)
        : quic_client(proto, client_options{}, std::move(config)) {
    }

    quic_client(protocol_type& proto, client_options options, quic::experimental::quic_client_config config)
        : base(proto, std::move(options), make_quic_client_socket(config), config.remote_address) {
    }
};

template<typename Serializer, typename MsgType = uint32_t>
class quic_server : public rpc::protocol<Serializer, MsgType>::server {
    using protocol_type = rpc::protocol<Serializer, MsgType>;
    using base = typename protocol_type::server;

public:
    quic_server(
            protocol_type& proto,
            quic::experimental::quic_server_config config,
            resource_limits memory_limit = resource_limits())
        : quic_server(proto, server_options{}, std::move(config), std::move(memory_limit)) {
    }

    quic_server(
            protocol_type& proto,
            server_options options,
            quic::experimental::quic_server_config config,
            resource_limits memory_limit = resource_limits())
        : base(proto, std::move(options), make_quic_server_socket(std::move(config)), std::move(memory_limit)) {
    }
};

} // namespace seastar::rpc::experimental
