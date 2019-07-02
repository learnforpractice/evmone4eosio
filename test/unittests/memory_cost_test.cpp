// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.

#include <evmone/memory_cost.hpp>
#include <gtest/gtest.h>

using namespace evmone;

constexpr auto number = uint128{0xcacacacacacacaca};
constexpr auto square = constexpr_mul(number, number);

static_assert(isqrt(square) == number);
static_assert(isqrt_ceil(square) == number);
static_assert(isqrt(square + 1) == number);
static_assert(isqrt_ceil(square + 1) == number + 1);
static_assert(isqrt(square - 1) == number - 1);
static_assert(isqrt_ceil(square - 1) == number);

static_assert(max_memory_size(std::numeric_limits<int64_t>::max()) == 2'199'023'231'008);
static_assert(max_memory_size(3 * 13 + 13 * 13 / 512) == 13 * 32);
static_assert(max_memory_size(3 * 23 + 23 * 23 / 512) == 23 * 32);
static_assert(max_memory_size(3 * 23 + 23 * 23 / 512 - 1) == 23 * 32);
static_assert(max_memory_size(3 * 23 + 23 * 23 / 512 + 1) == 24 * 32);

static_assert(max_memory_per_gas_bit(0) == 0);
static_assert(max_memory_per_gas_bit(1) == 32);
static_assert(max_memory_per_gas_bit(2) == 32);
static_assert(max_memory_per_gas_bit(3) == 96);
static_assert(max_memory_per_gas_bit(62) == 1554944231424);
static_assert(max_memory_per_gas_bit(63) == 2199023231008);

static_assert(max_memory_table[0] == 0);
static_assert(max_memory_table[31] == 33529888);
static_assert(max_memory_table[32] == 47428576);
static_assert(max_memory_table[33] == 47428576);
static_assert(max_memory_table[63] == 47428576);

static_assert(max_memory_size_for_gas(0) == 0);
static_assert(max_memory_size_for_gas(1) == 32);
static_assert(max_memory_size_for_gas(2) == 32);
static_assert(max_memory_size_for_gas(3) == 32);
static_assert(max_memory_size_for_gas(4) == 96);
static_assert(max_memory_size_for_gas(int64_t{1} << 30) == 33529888);
static_assert(max_memory_size_for_gas(int64_t{1} << 31) == 47428576);
static_assert(max_memory_size_for_gas(int64_t{1} << 32) == 47428576);
static_assert(max_memory_size_for_gas(int64_t{1} << 62) == 47428576);
