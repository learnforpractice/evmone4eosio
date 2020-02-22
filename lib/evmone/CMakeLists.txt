# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.

include(LibraryTools)

hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

message(STATUS +++++++++++++++++${CMAKE_SOURCE_DIR})

add_library(evmone SHARED
    ${include_dir}/evmone/evmone.h
    analysis.cpp
    analysis.hpp
    evmone.cpp
    execution.cpp
    execution.hpp
    instructions.cpp
    limits.hpp
    opcodes_helpers.h
    ${CMAKE_SOURCE_DIR}/test/utils/utils.cpp
    ${CMAKE_SOURCE_DIR}/../secp256k1/src/secp256k1.c
    ${CMAKE_SOURCE_DIR}/../ethash-0.4.4/lib/ethash/ethash.cpp
    ${CMAKE_SOURCE_DIR}/../ethash-0.4.4/lib/ethash/managed.cpp
    ${CMAKE_SOURCE_DIR}/../ethash-0.4.4/lib/ethash/keccak.c
    ${CMAKE_SOURCE_DIR}/../ethash-0.4.4/lib/ethash/keccakf800.c
    ${CMAKE_SOURCE_DIR}/../ethash-0.4.4/lib/ethash/keccakf1600.c
    ${CMAKE_SOURCE_DIR}/../ethash-0.4.4/lib/ethash/primes.c
    ${CMAKE_SOURCE_DIR}/../ethash-0.4.4/lib/ethash/progpow.cpp
)

target_link_libraries(evmone PUBLIC evmc::evmc PRIVATE intx::intx ethash::keccak ${EOSIOLIB_NATIVE} ${ETH_ACCOUNT_NATIVE})
target_include_directories(evmone PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/../secp256k1/src
    ${CMAKE_SOURCE_DIR}/../secp256k1
    ${CMAKE_SOURCE_DIR}/../secp256k1/include
    ${EOSIO_SOURCE_DIR}/externals/aleth/evm4eos
    ${EOSIOLIB_DIR}
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

set(COMMON_COMPILE_FLAGS ENABLE_MODULE_RECOVERY ENABLE_MODULE_ECDH USE_ECMULT_STATIC_PRECOMPUTATION USE_FIELD_INV_BUILTIN USE_NUM_NONE USE_SCALAR_INV_BUILTIN)
set(COMPILE_FLAGS USE_FIELD_5X52 USE_SCALAR_4X64 HAVE_BUILTIN_EXPECT HAVE___INT128)
target_compile_definitions(evmone PRIVATE ${COMMON_COMPILE_FLAGS} ${COMPILE_FLAGS})

set_target_properties(
    evmone
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_SOVERSION}
)

if(NOT SANITIZE)
    # On Linux, check if all symbols in evmone are resolved during linking.
    target_link_options(evmone PRIVATE $<$<PLATFORM_ID:Linux>:LINKER:--no-undefined>)
endif()

set_source_files_properties(evmone.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

add_standalone_library(evmone)
