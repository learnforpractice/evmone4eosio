#pragma once

#include "types.h"
#include "system.h"
#include "crypto.h"
#include "print.h"
#include "transaction.h"

#define EOSIO_THROW(msg) eosio_assert(false, msg)

#ifdef __WASM
    #define EOSIO_ASSERT(a, b) \
        eosio_assert(a, b);
#else
    #include "stacktrace.h"
    #define EOSIO_ASSERT(a, b) \
        if (!(a)) { \
            print_stacktrace(); \
        } \
        eosio_assert(a, b);
#endif

