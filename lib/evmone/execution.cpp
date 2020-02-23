// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#include "execution.hpp"
#include "analysis.hpp"

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <secp256k1_sha256.h>

#include <ethash/keccak.hpp>
#include "stacktrace.h"

#ifndef __WASM
#include <vm_api/vm_api.h>
#endif

//#include <eEVM/util.h>


#define EOSIO_ASSERT(a, b) \
    if (!(a)) { \
        print_stacktrace(); \
    } \
    eosio_assert(a, b);

#include <memory>

constexpr auto max_gas_limit = std::numeric_limits<int64_t>::max();
extern "C" EVMC_EXPORT int evm_recover_key(const uint8_t* _signature, uint32_t _signature_size, const uint8_t* _message, uint32_t _message_len, uint8_t* _serialized_public_key, uint32_t _serialized_public_key_size);

namespace evmone
{
evmc_result execute(evmc_vm* /*unused*/, const evmc_host_interface* host, evmc_host_context* ctx,
    evmc_revision rev, const evmc_message* msg, const uint8_t* code, size_t code_size)
{
    auto analysis = analyze(rev, code, code_size);

    auto state = std::make_unique<execution_state>();
    state->analysis = &analysis;
    state->msg = msg;
    state->code = code;
    state->code_size = code_size;
    state->host = evmc::HostContext{*host, ctx};
    state->gas_left = msg->gas;
    state->rev = rev;

    const auto* instr = &state->analysis->instrs[0];
    while (instr != nullptr)
        instr = instr->fn(instr, *state);

    const auto gas_left =
        (state->status == EVMC_SUCCESS || state->status == EVMC_REVERT) ? state->gas_left : 0;

    return evmc::make_result(
        state->status, gas_left, &state->memory[state->output_offset], state->output_size);
}
}  // namespace evmone

#include <iostream>
#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmone/evmone.h>
#include "../test/utils/utils.hpp"

#include "../../../eEVM/include/eEVM/rlp.h"
#include <eosiolib/system.h>
#include <eosiolib/crypto.h>
#include <eosiolib/print.h>
#include <eosiolib/transaction.h>

#include <eth_account.hpp>

using namespace eevm;
using namespace std::string_literals;
using namespace std;
using namespace evmc;

uint256be to_big_endian(int64_t balance) {
    uint256be _balance;

    for (int i=0;i<8;i++) {
        _balance.bytes[31-i] = ((uint8_t*)&balance)[i];
    }
    return _balance;
}

uint256be to_big_endian(const uint8_t* data, uint32_t size) {
    uint256be big_encoded{};
    EOSIO_ASSERT(size <=32, "size must <=32");
    for (int i=0;i<size;i++) {
        big_encoded.bytes[31-i] = data[i];
    }
    return big_encoded;
}

struct EVMLog {
    address addr;
    vector<uint8_t> data;
    vector<bytes32> topics;
};

inline std::string to_hex(const uint8_t* data, uint32_t size)
{
    static const auto hex_chars = "0123456789abcdef";
    std::string str;
    str.reserve(size * 2);
    for (int i=0;i<size;i++)
    {
        uint8_t b = data[i];
        str.push_back(hex_chars[uint8_t(b) >> 4]);
        str.push_back(hex_chars[uint8_t(b) & 0xf]);
    }
    return str;
}

class MyHost : public evmc::Host {
    /// @copydoc evmc_host_interface::account_exists
    evmc_tx_context tx_context{};

protected:
    vector<EVMLog> logs;

    // explicit ExampleHost(evmc_tx_context& _tx_context) noexcept : tx_context{_tx_context} {};
    // ExampleHost(evmc_tx_context& _tx_context, evmc::accounts& _accounts) noexcept
    //   : accounts{_accounts}, tx_context{_tx_context} {

    // };
public:
    explicit MyHost() noexcept {
        tx_context.block_number = tapos_block_num();
        tx_context.block_timestamp = current_time()/1000000;
    }

    virtual void append_logs(MyHost& host) {
        for (auto& log: host.logs) {
            logs.emplace_back(log);
        }
    }

    virtual vector<EVMLog>& get_logs() {
        return logs;
    }

    virtual bool account_exists(const address& addr) const override {
        eth_address _addr;
        memcpy(_addr.data(), addr.bytes, 20);
        return eth_account_exists(_addr);
    }

    /// @copydoc evmc_host_interface::get_storage
    virtual bytes32 get_storage(const address& addr, const bytes32& key) const override {
        eth_address _addr;
        key256 _key;
        value256 _value;
        bytes32 value;

        memcpy(_key.data(), key.bytes, 32);
        memcpy(_addr.data(), addr.bytes, 20);
        bool ret = eth_account_get_value(_addr, _key, _value);
        (void)ret;
        memcpy(value.bytes, _value.data(), 32);
        return value;
    }

    /// @copydoc evmc_host_interface::set_storage
    virtual evmc_storage_status set_storage(const address& addr,
                                            const bytes32& key,
                                            const bytes32& value) override {
        eth_address _addr;
        key256 _key;
        value256 _value;

        memcpy(_key.data(), key.bytes, 32);
        memcpy(_addr.data(), addr.bytes, 20);
        memcpy(_value.data(), value.bytes, 32);
        bool ret = eth_account_set_value(_addr, _key, _value);
        (void)ret;
        return EVMC_STORAGE_MODIFIED;

    // EVMC_STORAGE_UNCHANGED = 0
    // EVMC_STORAGE_MODIFIED = 1,
    // EVMC_STORAGE_MODIFIED_AGAIN = 2,
    // EVMC_STORAGE_ADDED = 3,
    // EVMC_STORAGE_DELETED = 4
    }

    /// @copydoc evmc_host_interface::get_balance
    virtual uint256be get_balance(const address& addr) const override {
        eth_address _addr;
        memcpy(_addr.data(), addr.bytes, 20);
        int64_t balance = eth_account_get_balance(_addr);
        return to_big_endian(balance);
    }

    /// @copydoc evmc_host_interface::get_code_size
    virtual size_t get_code_size(const address& addr) const override {
        eth_address _addr;
        memcpy(_addr.data(), addr.bytes, 20);
        return eth_account_get_code_size(_addr);
    }

    /// @copydoc evmc_host_interface::get_code_hash
    virtual bytes32 get_code_hash(const address& addr) const override {
        eth_address _addr;
        memcpy(_addr.data(), addr.bytes, 20);

        vector<uint8_t> code;
        eth_account_get_code(_addr, code);

        ethash::hash256 hash;
        memset(hash.bytes, 0, 32);

        if (code.size() == 0) {
            hash = ethash::keccak256((uint8_t*)"", 0);
        } else {
            hash = ethash::keccak256((const uint8_t*)code.data(), code.size());
        }
        return *((bytes32*)&hash);
    }

    /// @copydoc evmc_host_interface::copy_code
    virtual size_t copy_code(const address& addr,
                             size_t code_offset,
                             uint8_t* buffer_data,
                             size_t buffer_size) const override {
        (void)addr;
        (void)code_offset;
        (void)buffer_data;
        (void)buffer_size;
        return 0;
    }

    /// @copydoc evmc_host_interface::selfdestruct
    virtual void selfdestruct(const address& addr, const address& beneficiary) override {
        eth_address _addr;
        memcpy(_addr.data(), addr.bytes, 20);

        eth_address _addr_beneficiary;
        memcpy(_addr_beneficiary.data(), beneficiary.bytes, 20);

        int64_t balance_addr = eth_account_get_balance(_addr);
        int64_t balance_beneficiary = eth_account_get_balance(_addr_beneficiary);
        balance_beneficiary += balance_addr;

        eth_account_set_balance(_addr, 0);
        eth_account_set_balance(_addr_beneficiary, balance_beneficiary);
        eth_account_clear_code(_addr);
    }

#if 0
    enum evmc_status_code status_code;
    int64_t gas_left;
    const uint8_t* output_data;
    size_t output_size;
    evmc_release_result_fn release;
    evmc_address create_address;
    uint8_t padding[4];
#endif
    /// @copydoc evmc_host_interface::call
    virtual result call(const evmc_message& msg) override {
        static evmc_address ecrecover_address{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
        static evmc_address sha256_address{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
        static evmc_address ripemd160_address{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03};

        evmc_result res{};
        if (msg.destination == ecrecover_address) {
            EOSIO_ASSERT(msg.input_size == 128, "ecrecover: bad input size!");
            uint8_t _v[32];
            memcpy(_v, msg.input_data+32, 32);
            auto __v = to_big_endian(msg.input_data+32, 32);
            memcpy(_v, __v.bytes, 32);
            intx::uint256 v = intx::le::load<intx::uint256>(_v);
            vmelog("+++++++++++v: %d\n", (int)v);
            if (v >= 27 && v <= 28) {
                /*
                hash: 256bit
                v: 256bit
                r: 256bit
                s: 256bit
                */
                uint8_t hash[32];
                uint8_t public_key[65];
                uint8_t signature[65];
                const uint8_t *hash_message = msg.input_data;
                memset(public_key, 0, 65);
                memcpy(signature, msg.input_data+64, 64);
                signature[64] = uint8_t(v-27);
                evm_recover_key(signature, 65, hash_message, 32, public_key, 65);
                auto hash256 = ethash::keccak256(public_key+1, 64);

                memset(hash, 0, 32);
                memcpy(hash+12, (char*)&hash256 + 12, 20);
                res = evmc_make_result(EVMC_SUCCESS, 0, (uint8_t *)&hash, 32);
            }
            // bytes32 *r = (bytes32*)msg.input_data + 2;
            // bytes32 *s = (bytes32*)msg.input_data + 3;
            return result(res);
        } else if (msg.destination == sha256_address) {
            struct checksum256 hash{};
            sha256((char *)msg.input_data, msg.input_size, &hash);
            vmelog("++++++++++call sha256, input: %s\n", msg.input_data);
            res = evmc_make_result(EVMC_SUCCESS, 0, (uint8_t *)&hash, 32);
            return result(res);
        } else if (msg.destination == ripemd160_address) {
            uint8_t hash[32];
            memset(hash, 0, 32);
            ripemd160((char *)msg.input_data, msg.input_size, (struct checksum160*)&hash[12]);
            res = evmc_make_result(EVMC_SUCCESS, 0, hash, 32);
            return result(res);
        } else {
            vector<uint8_t> code;
            eth_account_get_code(*(eth_address*)&msg.destination, code);
            if (code.size()) {
                auto host = MyHost();
                auto evm = evmc::VM{evmc_create_evmone()};
                auto ret = evm.execute(host, EVMC_ISTANBUL, msg, code.data(), code.size());
                vmelog("++++++++gas left %d\n", ret.gas_left);
                append_logs(host);
                return ret;
            } else {
                return result(res);
            }
        }
    }

    /// @copydoc evmc_host_interface::get_tx_context
    virtual evmc_tx_context get_tx_context() const override {
        // memset((void *)&tx_context, 0, sizeof(tx_context));
        // tx_context.block_number = tapos_block_num();
        // tx_context.block_timestamp = current_time()/1000000;
        // tx_context.block_gas_limit = 0x7fffffffffffffff;
        // tx_context.chain_id.bytes[31] = 0x01;
        // tx_context.tx_origin.bytes[19] = 0x88;
        // tx_context.block_coinbase.bytes[19] = 0x89;

#if 0
    evmc_uint256be tx_gas_price;     /**< The transaction gas price. */
    evmc_address tx_origin;          /**< The transaction origin account. */
    evmc_address block_coinbase;     /**< The miner of the block. */
    //int64_t block_number;            /**< The block number. */
    //int64_t block_timestamp;         /**< The block timestamp. */
    //int64_t block_gas_limit;         /**< The block gas limit. */
    evmc_uint256be block_difficulty; /**< The block difficulty. */
    evmc_uint256be chain_id;         /**< The blockchain's ChainID. */
#endif
        return tx_context;
    }

    /// @copydoc evmc_host_interface::get_block_hash
    virtual bytes32 get_block_hash(int64_t block_number) const override {
        (void)block_number;
        return bytes32();
    }

    /// @copydoc evmc_host_interface::emit_log
    virtual void emit_log(const address& addr,
                          const uint8_t* data,
                          size_t data_size,
                          const bytes32 topics[],
                          size_t num_topics) override {
        EVMLog log;
        log.addr = addr;
        log.data.resize(data_size);
        memcpy(log.data.data(), data, data_size);
        for (uint32_t i=0;i<num_topics;i++) {
            log.topics.push_back(topics[i]);
        }
        logs.emplace_back(log);
    }
};

#if 0
enum evmc_call_kind
{
    EVMC_CALL = 0,         /**< Request CALL. */
    EVMC_DELEGATECALL = 1, /**< Request DELEGATECALL. Valid since Homestead.
                                The value param ignored. */
    EVMC_CALLCODE = 2,     /**< Request CALLCODE. */
    EVMC_CREATE = 3,       /**< Request CREATE. */
    EVMC_CREATE2 = 4       /**< Request CREATE2. Valid since Constantinople.*/
};

#endif

static secp256k1_context *s_ctx = nullptr;

extern "C" EVMC_EXPORT int evm_init() {
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return 0;
}

extern "C" EVMC_EXPORT int evm_get_account_id(const char* account, size_t account_size, const char* arbitrary_string, size_t arbitrary_string_size, char* hash160, size_t hash_size) {
    (void)arbitrary_string_size;

    EOSIO_ASSERT(hash_size == 20, "bad hash160 size!");
    EOSIO_ASSERT(account_size <= 13, "bad accoud size!");

    auto out = rlp::encode(account, arbitrary_string);
    auto hash256 = ethash::keccak256(out.data(), out.size());
    memcpy(hash160, (char*)&hash256 + 12, 20);
    return 0;
}

extern "C" EVMC_EXPORT int evm_recover_key(const uint8_t* _signature, uint32_t _signature_size, const uint8_t* _message, uint32_t _message_len, uint8_t* _serialized_public_key, uint32_t _serialized_public_key_size) {    
    if (_signature_size != 65 || _message_len != 32 || _serialized_public_key_size != 65) {
        return 0;
    }
    
    if (!s_ctx) {
        evm_init();
    }

#ifdef __WASM
    load_secp256k1_ecmult_static_context();
#endif
    // printhex(_signature, 65);
    // prints("\n");

    // printhex(_message, 32);
    // prints("\n");

    int v = _signature[64];
    EOSIO_ASSERT(v < 3, "bad signature");

    secp256k1_ecdsa_recoverable_signature recoverable_signature;
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(s_ctx, &recoverable_signature, _signature, v)) {
        return 0;
    }

    secp256k1_pubkey raw_pub_key;
    if (!secp256k1_ecdsa_recover(s_ctx, &raw_pub_key, &recoverable_signature, _message)) {
        return 0;
    }

    size_t serialized_pubkey_size = _serialized_public_key_size;
    secp256k1_ec_pubkey_serialize(s_ctx, _serialized_public_key, &serialized_pubkey_size, &raw_pub_key, SECP256K1_EC_UNCOMPRESSED);

    // printhex(_serialized_public_key, 65);
    // prints("\n");

    EOSIO_ASSERT(serialized_pubkey_size == _serialized_public_key_size, "eth_recover: bad size");
    // Expect single uint8_t header of value 0x04 -- uncompressed public key.
    EOSIO_ASSERT(_serialized_public_key[0] == 0x04, "eth_recover: bad value");
    return 1;
}

#if 0
struct evmc_message
{
    enum evmc_call_kind kind;
    uint32_t flags;
    int32_t depth;
    int64_t gas;
    evmc_address destination;
    evmc_address sender;
    const uint8_t* input_data;
    size_t input_size;
    evmc_uint256be value;
    evmc_bytes32 create2_salt;
#endif

/*
struct EVMLog {
    address addr;
    vector<uint8_t> data;
    vector<bytes32> topics;
};
*/

rlp::ByteString encode_topics(vector<bytes32>& topics) {
    rlp::ByteString bs, output;

    for (auto& topic: topics) {
        bs = rlp::ByteString(topic.bytes, topic.bytes + 20);
        bs = rlp::encode(bs);
        output.insert(output.end(), bs.begin(), bs.end());
    }

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    return output;
}

rlp::ByteString encode_log(EVMLog& log) {
    rlp::ByteString bs, output;

    bs = rlp::ByteString(log.addr.bytes, log.addr.bytes + 20);
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());
    
    bs = rlp::ByteString(log.data.data(), log.data.data() + log.data.size());
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());

    bs = encode_topics(log.topics);
    output.insert(output.end(), bs.begin(), bs.end());

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    return output;
}

rlp::ByteString encode_logs(vector<EVMLog>& logs) {
    rlp::ByteString output;
    for (auto& log: logs) {
        auto bs = encode_log(log);
        output.insert(output.end(), bs.begin(), bs.end());
    }

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    return output;
}

void print_result(evmc_address& address, const uint8_t* output_data, uint32_t output_size, vector<EVMLog>& logs) {
    vector<rlp::ByteString> vec;
    rlp::ByteString bs, output;

    bs = rlp::ByteString(address.bytes, address.bytes + 20);
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());
    
    bs = rlp::ByteString(output_data, output_data + output_size);
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());

    // auto logs = encode_logs(host.get_logs());
    // vec.emplace_back(logs);

    // output = rlp::encode(a, b);

    // rlp::ByteString prefix;
    // rlp::encode_details::prefix_multiple_length(output.size(), prefix);
    // printhex(prefix.data(), uint32_t(prefix.size()));
    // printhex(output.data(), uint32_t(output.size()));

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    printhex(output.data(), uint32_t(output.size()));
}

extern "C" EVMC_EXPORT int evm_execute(const uint8_t *raw_trx, size_t raw_trx_size, const char *sender_address, size_t sender_address_size) {
    EOSIO_ASSERT(sender_address_size == 20, "bad sender size");

    auto rlp_result = rlp::decode<uint256_t, uint256_t, uint256_t, rlp::ByteString, uint256_t, rlp::ByteString, uint8_t, uint256_t, uint256_t>(raw_trx, raw_trx_size);
    // std::cout << (uint64_t)std::get<0>(rlp_result) << std::endl; //nonce
    // std::cout << (uint64_t)std::get<1>(rlp_result) << std::endl; //gas_price
    // std::cout << (uint64_t)std::get<2>(rlp_result) << std::endl; //gas_limit

    evmc_address new_address;

    auto msg = evmc_message{};
    msg.gas = max_gas_limit;

//        std::cout << (uint64_t)std::get<3>(rlp_result) << std::endl; //to
    
    auto value = std::get<4>(rlp_result); //value
    memcpy(msg.value.bytes, intx::as_bytes(value), 32);

    // std::cout << (uint64_t)std::get<5>(rlp_result) << std::endl; // data
    uint8_t v = std::get<6>(rlp_result); //v
    auto r = std::get<7>(rlp_result); //r
    auto s = std::get<8>(rlp_result); //s

    if (r == 0 && s == 0) {
        memcpy(msg.sender.bytes, sender_address, 20);
    } else {
        uint8_t sig[65];
        memcpy(sig, intx::as_bytes(r), 32);
        memcpy(sig+32, intx::as_bytes(s), 32);
        sig[64] = v;
        uint8_t empty_data[32];
        memset(empty_data, 0, 32);
        auto hash256 = ethash::keccak256(empty_data, 32);
        uint8_t hash[32];
        evm_recover_key(sig, 65, (uint8_t *)&hash256, 32, hash, 32);
        hash256 = ethash::keccak256(hash, 32);
        printhex(&hash256, 32);
        memcpy(msg.sender.bytes, (char*)&hash256 + 12, 20);
    }

    uint32_t nonce = 0;
    bool ret = eth_account_get_nonce(*(eth_address *)&msg.sender, nonce);
    EOSIO_ASSERT(ret, "get_nonce: bad nonce");

    auto address = std::get<3>(rlp_result);
    if (address.size() == 0) {
        msg.kind = EVMC_CREATE;
        rlp::ByteString addr;
        addr.resize(20);
        memcpy(addr.data(), msg.sender.bytes, 20);
        auto res = rlp::encode(addr, nonce);
        auto hash = ethash::keccak256(res.data(), res.size());
        memcpy(new_address.bytes, (char*)&hash+12, 20);

        uint64_t creator = eth_account_find_creator_by_address(*(eth_address *)&msg.sender);
        eth_account_create(*(eth_address *)&new_address, creator);
        msg.destination = new_address;
    } else {
        EOSIO_ASSERT(address.size() == 20, "bad destination address");
        msg.kind = EVMC_CALL;
        memcpy(msg.destination.bytes, address.data(), 20);
    }
    vmelog("+++++++++++++++msg.kind %d\n", msg.kind);
    auto data = std::get<5>(rlp_result);

    if (msg.kind == EVMC_CREATE) {
        // msg.input_data = data.data();
        // msg.input_size = data.size();
        auto host = MyHost();
        auto evm = evmc::VM{evmc_create_evmone()};
        auto res = evm.execute(host, EVMC_ISTANBUL, msg, data.data(), data.size());
        eth_account_set_nonce(*(eth_address *)&msg.sender, nonce+1);
        vector<uint8_t> code(res.output_data, res.output_data + res.output_size);
        eth_account_set_code(*(eth_address*)&new_address, code);
        print_result(msg.destination, res.output_data, res.output_size, host.get_logs());
    } else if (msg.kind == EVMC_CALL) {
        msg.input_data = data.data();
        msg.input_size = data.size();
        vector<uint8_t> code;
        eth_account_get_code(*(eth_address*)&msg.destination, code);
        vmelog("+++++code size: %d\n", code.size());
        if (code.size() > 0) {
            auto host = MyHost();
            auto evm = evmc::VM{evmc_create_evmone()};
            auto res = evm.execute(host, EVMC_ISTANBUL, msg, code.data(), code.size());
            eth_account_set_nonce(*(eth_address *)&msg.sender, nonce+1);
            print_result(msg.destination, res.output_data, res.output_size, host.get_logs());
            vmelog("++++++res.output_size: %d status_code %d\n", res.output_size, res.status_code);
        }
    } else {
        EOSIO_ASSERT(0, "bad message kind");
    }

    return 1;
}


/*
struct evmc_result
{
    enum evmc_status_code status_code;
    int64_t gas_left;
    const uint8_t* output_data;
    size_t output_size;
    evmc_release_result_fn release;
    evmc_address create_address;
};
*/
