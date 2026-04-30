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

#include "quic_error_impl.hh"

#include <ngtcp2/ngtcp2.h>

#include <gnutls/gnutls.h>

namespace seastar::quic::experimental {

const char* to_string(quic_error error) noexcept {
    switch (error) {
    case quic_error::none:
        return "none";
    case quic_error::invalid_argument:
        return "invalid_argument";
    case quic_error::invalid_state:
        return "invalid_state";
    case quic_error::io:
        return "io";
    case quic_error::timeout:
        return "timeout";
    case quic_error::protocol:
        return "protocol";
    case quic_error::closed:
        return "closed";
    case quic_error::unsupported:
        return "unsupported";
    case quic_error::internal:
        return "internal";
    case quic_error::backend:
        return "backend";
    }
    return "unknown";
}

quic_exception::quic_exception(quic_error error, std::string detail)
    : std::runtime_error(detail.empty()
              ? std::string(to_string(error))
              : std::string(to_string(error)) + ": " + detail)
    , _error(error) {
}

quic_error quic_exception::code() const noexcept {
    return _error;
}

[[noreturn]] void throw_quic_error(quic_error error, std::string_view detail) {
    throw quic_exception(error, std::string(detail));
}

quic_error classify_ngtcp2_error(int code) noexcept {
    if (code == 0) {
        return quic_error::none;
    }
    if (code == NGTCP2_ERR_DRAINING) {
        return quic_error::closed;
    }
    if (code == NGTCP2_ERR_IDLE_CLOSE) {
        return quic_error::timeout;
    }
    if (code == NGTCP2_ERR_WRITE_MORE) {
        return quic_error::none;
    }
    if (code == NGTCP2_ERR_INVALID_ARGUMENT) {
        return quic_error::invalid_argument;
    }
    if (code == NGTCP2_ERR_PROTO) {
        return quic_error::protocol;
    }
    return quic_error::backend;
}

quic_error classify_gnutls_error(int code) noexcept {
    if (code >= 0) {
        return quic_error::none;
    }
    if (code == GNUTLS_E_AGAIN || code == GNUTLS_E_INTERRUPTED) {
        return quic_error::io;
    }
#ifdef GNUTLS_E_TIMEDOUT
    if (code == GNUTLS_E_TIMEDOUT) {
        return quic_error::timeout;
    }
#endif
    return quic_error::backend;
}

bool ngtcp2_is_write_more(int code) noexcept {
    return code == NGTCP2_ERR_WRITE_MORE;
}

bool ngtcp2_is_draining(int code) noexcept {
    return code == NGTCP2_ERR_DRAINING;
}

bool ngtcp2_is_idle_close(int code) noexcept {
    return code == NGTCP2_ERR_IDLE_CLOSE;
}

std::string ngtcp2_error_message(int code) {
    return ngtcp2_strerror(code);
}

std::string gnutls_error_message(int code) {
    return gnutls_strerror(code);
}

} // namespace seastar::quic::experimental
