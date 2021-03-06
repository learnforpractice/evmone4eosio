#pragma once
#include <evmc/evmc.h>
#include <evmc/evmc.hpp>

#include <evmone/evmone.h>

#include <intx/intx.hpp>
#include "eevm/rlp.h"
#include <eth_account.hpp>

using namespace evmc;
using namespace intx;
using namespace eevm;

struct evm_log {
    address addr;
    vector<uint8_t> data;
    vector<bytes32> topics;
};

static bytes32 zero_bytes32{};
static evmc_address EmptyAddress{};

uint256be to_uint256(int64_t value);
uint256be to_uint256(eth_uint256& value);
uint256be to_little_endian(int64_t value);
uint256be to_little_endian(const uint8_t* value, uint32_t size);
uint256be to_uint256(const uint8_t* data, uint32_t size, int endian=0);
uint32_t big_endian_to_uint32(const uint8_t* data, uint32_t size);
uint256be to_balance(const uint8_t* data, uint32_t size);
std::string to_hex(const uint8_t* data, uint32_t size);

const char *get_status_error(evmc_status_code& status_code);
void print_result(evmc_address& address, const uint8_t* output_data, size_t output_size, vector<evm_log>& logs);
result on_create(evmc_revision version, evmc_address& origin, const evmc_message& msg, const uint8_t* code, uint32_t code_size, vector<evm_log> &logs, evmc_address& new_address);
result on_call(evmc_revision version, const evmc_address& origin, const evmc_address& code_addr, const evmc_message& msg, vector<evm_log>& logs);
void evmc_transfer(const evmc_address& sender, const evmc_address& receiver, const evmc_uint256be& value);
extern "C" EVMC_EXPORT int evm_recover_key(const uint8_t* _signature, uint32_t _signature_size, const uint8_t* _message, uint32_t _message_len, uint8_t* _serialized_public_key, uint32_t _serialized_public_key_size);


rlp::ByteString encode_topics(vector<bytes32>& topics);
rlp::ByteString encode_log(evm_log& log);
rlp::ByteString encode_logs(vector<evm_log>& logs);
void print_result(evmc_address& address, const uint8_t* output_data, size_t output_size, vector<evm_log>& logs, int64_t gas_cost);
void check_chain_id(int32_t id);

bytes32 evm_keccak256(const uint8_t *input, size_t input_size);



/*
"0000000000000000000000000000000000000001": { "precompiled": { "name": "ecrecover", "linear": { "base": 3000, "word": 0 } }, "balance": "0x01" },
"0000000000000000000000000000000000000002": { "precompiled": { "name": "sha256", "linear": { "base": 60, "word": 12 } }, "balance": "0x01" },
"0000000000000000000000000000000000000003": { "precompiled": { "name": "ripemd160", "linear": { "base": 600, "word": 120 } }, "balance": "0x01" },
"0000000000000000000000000000000000000004": { "precompiled": { "name": "identity", "linear": { "base": 15, "word": 3 } }, "balance": "0x01" },
*/
struct contract_gas {
    int64_t base;
    int64_t word;
};

enum contract_type {
    contract_type_zero,
    contract_type_ecrecover,        //1
    contract_type_sha256,           //2
    contract_type_ripemd160,        //3
    contract_type_identity,         //4
    contract_type_modexp,           //5
    contract_type_alt_bn128_G1_add, //6
    contract_type_alt_bn128_G1_mul, //7
    contract_type_alt_bn128_pairing_product //8
};

int get_precompile_address_type(const evmc_address addr);
int64_t get_precompiled_contract_gas(contract_type type, size_t input_size);
