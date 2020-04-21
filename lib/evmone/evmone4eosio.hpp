#pragma once
#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmone/evmone.h>
#include "execution.hpp"
#include "../test/utils/utils.hpp"

#include "eevm/rlp.h"

#include <eth_account.hpp>
#include <evm_test.hpp>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <secp256k1_sha256.h>

#include <ethash/keccak.hpp>

#include <eosiolib_legacy/eosiolib.h>

#include "utility.hpp"

using namespace eevm;
using namespace std::string_literals;
using namespace std;
using namespace evmc;

#ifdef EVM_FOR_PASS_VMTESTS
#define EVMC_VERSION EVMC_ISTANBUL
#else
#define EVMC_VERSION EVMC_BYZANTIUM
#endif
// #define EVMC_VERSION EVMC_FRONTIER
// #define EVMC_VERSION EVMC_HOMESTEAD
// #define EVMC_VERSION EVMC_TANGERINE_WHISTLE

void print_result(evmc_address& address, const uint8_t* output_data, size_t output_size, vector<evm_log>& logs);
result on_create(evmc_revision version, evmc_address& origin, const evmc_message& msg, const uint8_t* code, uint32_t code_size, vector<evm_log> &logs, evmc_address& new_address);
result on_call(evmc_revision version, const evmc_address& origin, const evmc_address& code_addr, const evmc_message& msg, vector<evm_log>& logs);
void evm_exec_test(const uint8_t* tests, uint32_t size);


