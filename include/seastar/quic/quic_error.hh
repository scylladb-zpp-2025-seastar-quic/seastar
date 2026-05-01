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

#include <stdexcept>
#include <string>
#include <string_view>

namespace seastar::quic::experimental {

enum class quic_error_code {
    none = 0,
    invalid_argument,
    invalid_state,
    io,
    timeout,
    protocol,
    closed,
    unsupported,
    internal,
    backend,
};

const char* to_string(quic_error_code error) noexcept;

class quic_error final : public std::runtime_error {
public:
    explicit quic_error(quic_error_code error, std::string detail = {});

    quic_error_code code() const noexcept;

private:
    quic_error_code _error;
};

} // namespace seastar::quic::experimental
