# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2019 Pawel Bylica.
# Licensed under the Apache License, Version 2.0.
if (EOSIOLIB_NATIVE)
include(LibraryTools)

hunter_add_package(intx)
find_package(intx CONFIG REQUIRED)

message(STATUS +++++++++++++++++${CMAKE_SOURCE_DIR})

add_library(evmone SHARED
    ${include_dir}/evmone/evmone.h
    evmhost.cpp
    evmhost.hpp
    utility.cpp
    utility.hpp
    evmone4eosio_test.cpp

    analysis.cpp
    analysis.hpp
    evmone.cpp
    evmone4eosio.cpp
    execution.cpp
    execution.hpp
    instructions.cpp
    limits.hpp
    opcodes_helpers.h
#    ${CMAKE_SOURCE_DIR}/ethereum_vm/eth_account.cpp
    ${CMAKE_SOURCE_DIR}/ethereum_vm/eth_account.hpp

    ${CMAKE_SOURCE_DIR}/test/utils/utils.cpp
    ${CMAKE_SOURCE_DIR}/secp256k1/src/secp256k1.c
    ${CMAKE_SOURCE_DIR}/ethash/lib/ethash/ethash.cpp
    ${CMAKE_SOURCE_DIR}/ethash/lib/ethash/managed.cpp
    ${CMAKE_SOURCE_DIR}/ethash/lib/keccak/keccak.c
    ${CMAKE_SOURCE_DIR}/ethash/lib/keccak/keccakf800.c
    ${CMAKE_SOURCE_DIR}/ethash/lib/keccak/keccakf1600.c
    ${CMAKE_SOURCE_DIR}/ethash/lib/ethash/primes.c
    ${CMAKE_SOURCE_DIR}/ethash/lib/ethash/progpow.cpp
)

set(INC_DIRS 
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include/eosiolib/contracts
    ${CMAKE_SOURCE_DIR}/include/eosiolib/core
    ${CMAKE_SOURCE_DIR}/include/eosiolib/capi
    ${CMAKE_SOURCE_DIR}/ethereum_vm
    ${CMAKE_SOURCE_DIR}/secp256k1/src
    ${CMAKE_SOURCE_DIR}/secp256k1
    ${CMAKE_SOURCE_DIR}/secp256k1/include
    ${CMAKE_SOURCE_DIR}/ethash/include
    # ${EOSIO_SOURCE_DIR}/externals/aleth/evm4eos
    # ${EOSIOLIB_DIR}
    $<BUILD_INTERFACE:${include_dir}>$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(evmone PUBLIC evmc::evmc PRIVATE intx::intx ethash::keccak ${EOSIOLIB_NATIVE} ${ETH_ACCOUNT_NATIVE})
target_include_directories(evmone PUBLIC ${INC_DIRS})

set(COMMON_COMPILE_FLAGS ENABLE_MODULE_RECOVERY ENABLE_MODULE_ECDH USE_ECMULT_STATIC_PRECOMPUTATION USE_FIELD_INV_BUILTIN USE_NUM_NONE USE_SCALAR_INV_BUILTIN)
set(COMPILE_FLAGS USE_FIELD_5X52 USE_SCALAR_4X64 HAVE_BUILTIN_EXPECT HAVE___INT128)
target_compile_definitions(evmone PRIVATE -DEOSIO_NATIVE ${COMMON_COMPILE_FLAGS} ${COMPILE_FLAGS})

set_target_properties(
    evmone
    PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_SOVERSION}
)

if(NOT SANITIZE)
    # On Linux, check if all symbols in evmone are resolved during linking.
#    target_link_options(evmone PRIVATE $<$<PLATFORM_ID:Linux>:LINKER:--no-undefined>)
endif()

set_source_files_properties(evmone.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="${PROJECT_VERSION}")

add_standalone_library(evmone)

# add_executable(evmone_test test.cpp
#     ${CMAKE_SOURCE_DIR}/ethereum_vm/eth_account.cpp
#     ${CMAKE_SOURCE_DIR}/ethereum_vm/eth_account.hpp
# )

# target_include_directories(evmone_test PUBLIC ${INC_DIRS})

# target_link_libraries(evmone_test PUBLIC evmc::evmc PRIVATE intx::intx ethash::keccak ${EOSIOLIB_NATIVE})
# target_include_directories(evmone_test PUBLIC ${INC_DIRS})
# target_compile_definitions(evmone_test PRIVATE -DEOSIO_NATIVE ${COMMON_COMPILE_FLAGS} ${COMPILE_FLAGS})

else()

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package( eosio.cdt REQUIRED )

set(COMMON_SRC
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include/evmone/evmone.h
    evmhost.cpp
    evmhost.hpp
    utility.cpp

    analysis.cpp
    analysis.hpp
    evmone.cpp
    evmone4eosio.cpp
    execution.cpp
    execution.hpp
    instructions.cpp
    limits.hpp
    opcodes_helpers.h

    ${CMAKE_CURRENT_SOURCE_DIR}/../../test/utils/utils.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../intx/lib/intx/div.cpp    
    ${CMAKE_CURRENT_SOURCE_DIR}/../../secp256k1/src/secp256k1.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/lib/ethash/ethash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/lib/ethash/managed.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/lib/keccak/keccak.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/lib/keccak/keccakf800.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/lib/keccak/keccakf1600.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/lib/ethash/primes.c
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/lib/ethash/progpow.cpp
)

set(EVM_INCLUDES 
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm
    ${CMAKE_CURRENT_SOURCE_DIR}/../../evmc/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../intx/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../secp256k1/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../../secp256k1
    ${CMAKE_CURRENT_SOURCE_DIR}/../../secp256k1/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethash/include
)

add_contract(ethereum_vm ethereum_vm 
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm/eth_account.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm/eth_account.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm/ethereum_vm.cpp
    ${COMMON_SRC}
)

#target_link_libraries(evmone PUBLIC evmc::evmc PRIVATE intx::intx ethash::keccak ${EOSIOLIB_NATIVE} ${ETH_ACCOUNT_NATIVE})
target_include_directories(ethereum_vm PUBLIC
    ${EVM_INCLUDES}
)
#-DUSE_INTRINSIC_EVM_EXECUTE 
set(COMMON_COMPILE_FLAGS ENABLE_MODULE_RECOVERY ENABLE_MODULE_ECDH USE_ECMULT_STATIC_PRECOMPUTATION USE_FIELD_INV_BUILTIN USE_NUM_NONE USE_SCALAR_INV_BUILTIN)
set(COMPILE_FLAGS USE_FIELD_5X52 USE_SCALAR_4X64 HAVE_BUILTIN_EXPECT HAVE___INT128)
target_compile_definitions(ethereum_vm PRIVATE -D__WASM ${COMMON_COMPILE_FLAGS} ${COMPILE_FLAGS})

configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm/ethereum_vm.abi ${CMAKE_CURRENT_BINARY_DIR}/ethereum_vm.abi @COPYONLY )


add_contract(evmtest evmtest
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm/eth_account.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm/eth_account.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../../ethereum_vm/evmtest.cpp
    evmone4eosio_test.cpp
    ${COMMON_SRC}
)

#target_link_libraries(evmone PUBLIC evmc::evmc PRIVATE intx::intx ethash::keccak ${EOSIOLIB_NATIVE} ${ETH_ACCOUNT_NATIVE})
target_include_directories(evmtest PUBLIC
    ${EVM_INCLUDES}
)

#-DUSE_INTRINSIC_EVM_EXECUTE
set(COMMON_COMPILE_FLAGS ENABLE_MODULE_RECOVERY ENABLE_MODULE_ECDH USE_ECMULT_STATIC_PRECOMPUTATION USE_FIELD_INV_BUILTIN USE_NUM_NONE USE_SCALAR_INV_BUILTIN)
set(COMPILE_FLAGS USE_FIELD_5X52 USE_SCALAR_4X64 HAVE_BUILTIN_EXPECT HAVE___INT128)
target_compile_definitions(evmtest PRIVATE -D__WASM ${COMMON_COMPILE_FLAGS} ${COMPILE_FLAGS})

endif()
