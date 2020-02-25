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


#ifndef __WASM
extern "C" void vmelog_(int line, const char *file, const char *func, const char *fmt, ...);
#define ENDC "\033[0m"
#define vmelog(fmt...) \
    printf("\033[91m%d %s %s", __LINE__, __FILE__, __FUNCTION__); \
    printf(fmt); \
    printf(ENDC);
#else
    #define vmelog(fmt...)
#endif