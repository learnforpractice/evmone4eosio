#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>

using int128 = __int128;

int64_t cisqrt(int128 x) noexcept
{
    return static_cast<int64_t>(ceil(sqrt((double)x)));
}

int clz(unsigned __int128 x)
{
    auto hi = uint64_t(x >> 64);
    auto lo = uint64_t(x);
    return hi != 0 ? __builtin_clzll(hi) : lo != 0 ? __builtin_clzll(lo) + 64 : 128;
}

 int128 isqrt(int128 n) noexcept
{
    // The number of 2-bit digits.
    auto s = (128 - clz(n) + 1) & ~1;

    int128 r = 0;
    while ((s -= 2) >= 0)
    {
        r <<= 1;
        r += ((r + 1) * (r + 1) <= (n >> s));
    }

    return r;
}

 int128 isqrt_ceil(int128 n) noexcept
{
         auto r = isqrt(n);
    r += (r * r != n);
    return r;
}

int128 integerSqrt(int128 n) noexcept
{
    // Find greatest shift.
    auto s = (128 - clz(n) + 1) & ~1;

    //    std::cerr << (int64_t)n << " " << z << " " << shift << "\n";

    // Find digits of result.
    int128 r = 0;
    while ((s -= 2) >= 0)
    {
        r <<= 1;
        r += ((r + 1) * (r + 1) <= (n >> s));
    }

    // The result contains the floor(sqrt(n)).

    if (r * r != n)
        r += 1;

    return r;
}


int128 memory_cost(int64_t w) noexcept
{
    return int128{w} * 3 + int128{w} * w / 512;
}

int64_t max_num_words(int128 g) noexcept
{
    return -768 + isqrt_ceil(256 * (2 * g + 2 * 1152));
}

int64_t max_memory_per_gas_bit(int c) noexcept
{
    auto m = (uint64_t{1} << c)- 1;
    return max_num_words(m) * 32;
}


int test_max_words()
{
    int64_t w = 0;
    while (true)
    {
        auto g = memory_cost(w);
        auto m = max_num_words(g);

        if (m < w)
        {
            std::cout << (int64_t)g << " " << w << " " << m << "\n";
            return 1;
        }

        if (m > w)
        {
            std::cout << (int64_t)g << " " << w << " " << m << "\n";
            return 2;
        }

        if (w % 100000000 == 0)
        {
            std::cout << (int64_t)g << " " << w << " " << m << "\n";
        }

        if (g > std::numeric_limits<int64_t>::max())
        {
            std::cout << (int64_t)g << " " << w << " " << m << "\n";
            return 0;
        }

        ++w;
    }
}

int test_isqrt()
{
    int128 start = int128{1} << 50;
    for (int128 i = start; i < start + 1000000000; ++i)
    {
        auto a = cisqrt(i);
        auto b = isqrt_ceil(i);
        //        auto b = isqrt(i);
        if (a != b)
        {
            std::cout << (int64_t)i << " " << (int64_t)a << " " << (int64_t)b << "\n";
            return 1;
        }

        if (i % 100000000 == 0)
        {
            std::cout << (int64_t)i << " " << (int64_t)a << " " << (int64_t)b << "\n";
        }
    }
    return 0;
}

int print_table()
{
    for (int i = 0; i <= 64; ++i)
    {
        std::cout << i << ": " << max_memory_per_gas_bit(i) << "\n";
    }
    return 0;
}

int main()
{
    print_table();
//    return test_isqrt();
//        return test_max_words();
}
