// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 The evmone Authors.
// Licensed under the Apache License, Version 2.0.
#pragma once

#include <intx/int128.hpp>
#include <array>
#include <memory>

namespace evmone
{
using intx::uint128;

constexpr int clz(uint64_t x) noexcept
{
    if (x == 0)
        return 64;

    auto c = int{0};
    while ((x & (uint64_t{1} << 63)) == 0)
    {
        c++;
        x <<= 1;
    };
    return c;
}

constexpr int constexpr_clz(uint128 x) noexcept
{
    return x.hi == 0 ? clz(x.lo) | 64 : clz(x.hi);
}

constexpr uint128 isqrt(uint128 n) noexcept
{
    // The number of 2-bit digits.
    auto s = (128 - constexpr_clz(n) + 1) & ~1;

    auto r = uint128{0};
    while ((s -= 2) >= 0)
    {
        r <<= 1;
        r += (intx::constexpr_mul(r + 1, r + 1) <= (n >> s));
    }

    return r;
}

constexpr uint128 isqrt_ceil(uint128 n) noexcept
{
    auto r = isqrt(n);
    r += (intx::constexpr_mul(r, r) != n);
    return r;
}

constexpr int64_t max_memory_words(int64_t gas) noexcept
{
    return isqrt_ceil(constexpr_mul(uint128{gas}, 512) + 589824).lo - 768;
}

constexpr int64_t max_memory_size(int64_t gas) noexcept
{
    return max_memory_words(gas) * 32;
}

constexpr int64_t max_memory_per_gas_bit(int c) noexcept
{
    return max_memory_size(std::numeric_limits<int64_t>::max() >> (63 - c));
}

constexpr auto memory_physical_limit = max_memory_per_gas_bit(32);

constexpr auto max_memory_table = []() noexcept
{
    auto table = std::array<uint32_t, 64>{};
    for (auto i = 0; i < 64; ++i)
        table[i] = std::min(max_memory_per_gas_bit(i), memory_physical_limit);
    return table;
}
();

constexpr auto max_memory_size_for_gas(int64_t gas) noexcept
{
    return max_memory_table[64 - clz(gas)];
}


struct evm_memory
{
    int size = 0;
    std::unique_ptr<uint8_t[]> memory;

    explicit evm_memory(int64_t gas_limit) noexcept
      : memory{new uint8_t[max_memory_size_for_gas(gas_limit)]}
    {}
};

}  // namespace evmone
