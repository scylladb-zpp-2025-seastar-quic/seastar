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
 * Copyright 2026-present ScyllaDB
 */

#pragma once

#include <seastar/core/shared_ptr.hh>

namespace seastar::tests {

// Mutual-conversion probe: used to check that only implicit conversions /
// implicit constructors are selected on a value path (e.g. co_return,
// promise::set_value). If an explicit ctor/operator were selected instead, the
// conversion would throw.
struct explisyt;
struct implicit {
    implicit() = default;
    implicit(explisyt &&) {}
    operator explisyt();
};
struct explisyt {
    explisyt() = default;
    explicit operator implicit() {
        throw 42;
    }
    explicit explisyt(implicit &&) {
        throw 42;
    }
};
inline implicit::operator explisyt() { return {}; }

// Throws if copied. Use to assert that a value path never copies the returned
// value (only moves or constructs in place).
struct thrower_on_copy {
    thrower_on_copy() = default;
    thrower_on_copy(const thrower_on_copy&) { throw 42; }
    thrower_on_copy(thrower_on_copy&&) = default;
    ~thrower_on_copy() = default;
};

// Counts copies and moves into a shared state, so all instances spawned from
// the original (by copy or move) report into the same counters. Default-
// constructed instances get a fresh shared state; construct multiple related
// ones by copying/moving an original.
struct copy_move_counter {
    struct counts { int copies = 0; int moves = 0; };
    lw_shared_ptr<counts> shared = make_lw_shared<counts>();

    copy_move_counter() = default;
    copy_move_counter(const copy_move_counter& o) noexcept : shared(o.shared) {
        ++shared->copies;
    }
    copy_move_counter(copy_move_counter&& o) noexcept : shared(o.shared) {
        ++shared->moves;
    }
    copy_move_counter& operator=(const copy_move_counter& o) noexcept {
        shared = o.shared;
        ++shared->copies;
        return *this;
    }
    copy_move_counter& operator=(copy_move_counter&& o) noexcept {
        shared = o.shared;
        ++shared->moves;
        return *this;
    }
    ~copy_move_counter() = default;

    // Extra moves introduced by the co_await round-trip
    constexpr static auto co_await_moves = 2;
};

struct move_counter : copy_move_counter {
    using copy_move_counter::copy_move_counter;
    move_counter(const move_counter&) = delete;
    move_counter(move_counter&&) noexcept = default;
    move_counter& operator=(const move_counter&) = delete;
    move_counter& operator=(move_counter&&) noexcept = default;
};

} // namespace seastar::tests
