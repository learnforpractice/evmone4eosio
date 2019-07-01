#include <cmath>
#include <cstdint>
#include <iostream>
#include <limits>

using int128 = __int128;

int64_t cisqrt(int128 x) noexcept
{
    return static_cast<int64_t>(ceil(sqrt((double)x)));
}

int128 newton(int128 n) noexcept
{
    if (n == 0)
        return 0;

    int128 y = 0;
    int128 x = 2;
    while (y != x && y != x + 1)
    {
        y = x;
        x = (x + n / x) / 2;
    }

    if (x * x != n)
        x += 1;

    return x;
}

int128 integerSqrt(int128 n) noexcept
{
    // Find greatest shift.
    int shift = 2;
    auto nShifted = n >> shift;
    while (nShifted != 0)
    {
        shift += 2;
        nShifted = n >> shift;
    }
    shift -= 2;

    // Find digits of result.
    int128 result = 0;
    while (shift >= 0)
    {
        result <<= 1;
        auto candidateResult = result + 1;
        if (candidateResult * candidateResult <= (n >> shift))
            result = candidateResult;
        shift -= 2;
    }

    // The result contains the floor(sqrt(n)).

    if (result * result != n)
        result += 1;

    return result;
}


int128 isqrt(int128 x) noexcept
{
    int128 op, res, one;

    op = x;
    res = 0;

    /* "one" starts at the highest power of four <= than the argument. */
    one = int128{1} << (128 - 2);  /* second-to-top bit set */
    while (one > op) one >>= 2;

    while (one != 0) {
        if (op >= res + one) {
            op -= res + one;
            res += one << 1;  // <-- faster than 2 * one
        }
        res >>= 1;
        one >>= 2;
    }

    //return res;

    if (res*res != x)
        res +=1;

    return res;
}


int128 memory_cost(int64_t w) noexcept
{
    return int128{w} * 3 + int128{w} * w / 512;
}

int64_t max_num_words(int128 g) noexcept
{
    return -768 + cisqrt(256 * (2 * g + 2 * 1152));
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

        if (w % 1000000000 == 0)
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
    for (int128 i = 0; i < 100000000; ++i)
    {
        auto a = cisqrt(i);
        auto b = integerSqrt(i);
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

int main()
{
    return test_isqrt();
    //    return test_max_words();
}
