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
 * Copyright 2024 ScyllaDB
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace seastar::internal::crypto {

/// \brief Result of an MD5 hash computation (16 bytes).
struct md5_hash {
    std::array<uint8_t, 16> data;
};

/// \brief Incremental MD5 hash computation.
///
/// Wraps a backend-specific MD5 context with inline opaque storage,
/// avoiding dynamic allocation for the handle wrapper itself.  Both
/// GnuTLS and OpenSSL backend handles fit within \c max_ctx_size bytes.
///
/// Usage:
/// \code
///   auto h = crypto::make_md5_hasher();
///   h.update(data1, len1);
///   h.update(data2, len2);
///   auto hash = h.finalize();
/// \endcode
class md5_hasher {
public:
    /// Maximum size of inline storage for a backend-specific context handle.
    static constexpr size_t max_ctx_size = sizeof(void*);

    /// Backend operation table.  Populated by each crypto backend.
    struct ops {
        void (*update)(unsigned char* ctx, const void* data, size_t len);
        md5_hash (*finalize)(unsigned char* ctx);
        void (*destroy)(unsigned char* ctx);
    };

    /// Construct with a backend ops table.  The caller must placement-
    /// construct the backend handle into ctx() before use.
    explicit md5_hasher(const ops* ops_table) noexcept : _ops(ops_table) {}

    ~md5_hasher() {
        if (_ops) {
            _ops->destroy(_ctx);
        }
    }

    md5_hasher(md5_hasher&& o) noexcept : _ops(o._ops) {
        std::memcpy(_ctx, o._ctx, max_ctx_size);
        o._ops = nullptr;
    }

    md5_hasher& operator=(md5_hasher&& o) noexcept {
        if (this != &o) {
            if (_ops) {
                _ops->destroy(_ctx);
            }
            _ops = o._ops;
            std::memcpy(_ctx, o._ctx, max_ctx_size);
            o._ops = nullptr;
        }
        return *this;
    }

    md5_hasher(const md5_hasher&) = delete;
    md5_hasher& operator=(const md5_hasher&) = delete;

    /// \brief Feed data into the hash computation.
    void update(const void* data, size_t len) {
        _ops->update(_ctx, data, len);
    }

    /// \brief Finalize and return the 16-byte MD5 hash.
    ///
    /// The hasher is consumed; it must not be used after this call.
    md5_hash finalize() {
        auto result = _ops->finalize(_ctx);
        _ops = nullptr;
        return result;
    }

    /// \brief Access the raw inline context storage for backend initialization.
    unsigned char* ctx() noexcept { return _ctx; }

private:
    const ops* _ops;
    alignas(void*) unsigned char _ctx[max_ctx_size];
};

/// \brief Create an MD5 hasher using the process-wide crypto provider.
md5_hasher make_md5_hasher();

} // namespace seastar::internal::crypto
