#include "evmhost.hpp"
#include <ethash/keccak.hpp>

#include <eosiolib_legacy/eosiolib.h>

EVMHost::EVMHost(const evmc_tx_context& ctx, evmc_revision _version) noexcept {
    tx_context = ctx;
    version = _version;
}

EVMHost::EVMHost(const evmc_address& _origin, evmc_revision _version) noexcept {
    tx_context.block_difficulty = {};
    tx_context.block_coinbase = {};
    tx_context.tx_origin = _origin;
    tx_context.block_number = tapos_block_num();
    tx_context.block_timestamp = current_time()/1000000;
    tx_context.block_gas_limit = max_gas_limit;
    int32_t id = eth_get_chain_id();
    tx_context.chain_id = to_little_endian(id);
    tx_context.tx_gas_price = {};
    version = _version;
}

void EVMHost::append_logs(vector<evm_log>& _logs) {
    for (auto& log: _logs) {
        logs.emplace_back(log);
    }
}

vector<evm_log>& EVMHost::get_logs() {
    return logs;
}

bool EVMHost::account_exists(const address& addr) const {
    return eth_account_exists(*(eth_address*)addr.bytes);
}

bytes32 EVMHost::get_storage(const address& addr, const bytes32& key) const {
    bytes32 value{};
    bool ret = eth_account_get_value(*(eth_address*)&addr, *(key256*)&key, *(value256*)&value);
    return value;
}

evmc_storage_status EVMHost::set_storage(const address& addr,
                                        const bytes32& key,
                                        const bytes32& value) {
    bytes32 old_value{};
    bool old_value_exists = eth_account_get_value(*(eth_address*)&addr, *(key256*)&key, *(value256*)&old_value);

    if (!old_value_exists && value != zero_bytes32) {
        eth_account_set_value(*(eth_address*)&addr, *(key256*)&key, *(value256*)&value);
        return EVMC_STORAGE_ADDED;
    } else if (old_value_exists && value == zero_bytes32) {
        eth_account_clear_value(*(eth_address*)&addr, *(key256*)&key);
        return EVMC_STORAGE_DELETED;
    } else {
        if (old_value != value) {
            eth_account_set_value(*(eth_address*)&addr, *(key256*)&key, *(value256*)&value);
        }
        return EVMC_STORAGE_MODIFIED;
    }

// EVMC_STORAGE_UNCHANGED = 0
// EVMC_STORAGE_MODIFIED = 1,
// EVMC_STORAGE_MODIFIED_AGAIN = 2,
// EVMC_STORAGE_ADDED = 3,
// EVMC_STORAGE_DELETED = 4
}

uint256be EVMHost::get_balance(const address& addr) const {
    auto balance = eth_account_get_balance(ETH_ADDRESS(addr));
    //convert balance from little endian to big endian
    return to_uint256(balance);
}

size_t EVMHost::get_code_size(const address& addr) const {
    return eth_account_get_code_size(ETH_ADDRESS(addr));
}

bytes32 EVMHost::get_code_hash(const address& addr) const {
    vector<uint8_t> code;
    eth_account_get_code(ETH_ADDRESS(addr), code);

    ethash::hash256 hash;
    memset(hash.bytes, 0, 32);

    if (code.size() == 0) {
        hash = ethash::keccak256((uint8_t*)"", 0);
    } else {
        hash = ethash::keccak256((const uint8_t*)code.data(), code.size());
    }
    return *((bytes32*)&hash);
}

size_t EVMHost::copy_code(const address& addr,
                            size_t code_offset,
                            uint8_t* buffer_data,
                            size_t buffer_size) const {
    vector<uint8_t> code;
    eth_account_get_code(ETH_ADDRESS(addr), code);

    if (code_offset >= code.size())
        return 0;

    const auto n = std::min(buffer_size, code.size() - code_offset);

    if (n > 0)
        std::copy_n(&code[code_offset], n, buffer_data);
    return n;
}

void EVMHost::selfdestruct(const address& addr, const address& beneficiary) {
    uint64_t creator = eth_account_find_creator_by_address(ETH_ADDRESS(addr));
    require_auth(creator);
    auto _balance_addr = eth_account_get_balance(ETH_ADDRESS(addr));
    auto _balance_beneficiary = eth_account_get_balance(ETH_ADDRESS(beneficiary));
    uint256_t& balance_addr = *(uint256_t*)&_balance_addr;
    uint256_t& balance_beneficiary = *(uint256_t*)&_balance_beneficiary;

    balance_beneficiary += balance_addr;
    if (balance_beneficiary < balance_addr) {
        EOSIO_THROW("balance_beneficiary amount overflow!");
    }

    eth_uint256 zero{};
    eth_account_set_balance(ETH_ADDRESS(addr), zero, creator);
    eth_account_set_balance(ETH_ADDRESS(beneficiary), _balance_beneficiary, 0);
    eth_account_clear_code(ETH_ADDRESS(addr));
}

result EVMHost::call(const evmc_message& msg) {
    vector<evm_log> _logs;
    if (msg.kind == EVMC_CREATE) {
        evmc_address new_address;
        result res = on_create(version, tx_context.tx_origin, msg, msg.input_data, (uint32_t)msg.input_size, _logs, new_address);
        if (res.status_code != EVMC_SUCCESS) {
            EOSIO_THROW(get_status_error(res.status_code));
        }
        append_logs(_logs);
        return res;
    } else if (msg.kind == EVMC_CALL || msg.kind == EVMC_DELEGATECALL || msg.kind == EVMC_CALLCODE) {
        auto res = on_call(version, tx_context.tx_origin, msg, _logs);
        if (res.status_code != EVMC_SUCCESS) {
            EOSIO_THROW(get_status_error(res.status_code));
        }
        append_logs(_logs);
        return res;
    } else {
        EOSIO_THROW("bad call kind");
        auto res = evmc_make_result(EVMC_SUCCESS, 0, nullptr, 0);
        return result(res);
    }
}

evmc_tx_context EVMHost::get_tx_context() const {
    return tx_context;
}

bytes32 EVMHost::get_block_hash(int64_t block_number) const {
    (void)block_number;
    return bytes32();
}

void EVMHost::emit_log(const address& addr,
                        const uint8_t* data,
                        size_t data_size,
                        const bytes32 topics[],
                        size_t num_topics) {
    evm_log log;
    log.addr = addr;
    log.data.resize(data_size);
    memcpy(log.data.data(), data, data_size);
    for (uint32_t i=0;i<num_topics;i++) {
        log.topics.push_back(topics[i]);
    }
    logs.emplace_back(log);
}

/*
"0000000000000000000000000000000000000001": { "precompiled": { "name": "ecrecover", "linear": { "base": 3000, "word": 0 } }, "balance": "0x01" },
"0000000000000000000000000000000000000002": { "precompiled": { "name": "sha256", "linear": { "base": 60, "word": 12 } }, "balance": "0x01" },
"0000000000000000000000000000000000000003": { "precompiled": { "name": "ripemd160", "linear": { "base": 600, "word": 120 } }, "balance": "0x01" },
"0000000000000000000000000000000000000004": { "precompiled": { "name": "identity", "linear": { "base": 15, "word": 3 } }, "balance": "0x01" },
*/
struct contract_gas {
    int base;
    int word;
};

contract_gas contracts_gas[] = {
    {3000,0},
    {60,12},
    {600,120},
    {15,3}
};

enum contract_type {
    type_ecrecover,
    type_sha256,
    type_ripemd160,
    type_identity
};

int64_t get_precompiled_contract_gas(contract_type type, size_t input_size) {
//size_t input_size, int64_t base_gas, int64_t word_gas
    EOSIO_ASSERT(type <= type_identity, "bad contract type");
    int64_t base_gas = contracts_gas[(int)type].base;
    int64_t word_gas = contracts_gas[(int)type].word;
    return base_gas + (input_size + 31) / 32 * word_gas;
}

result on_call(evmc_revision version, evmc_address& origin, const evmc_message& msg, vector<evm_log>& logs) {
    static evmc_address ecrecover_address{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
    static evmc_address sha256_address{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02};
    static evmc_address ripemd160_address{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x03};
    static evmc_address identity_address{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04};
//DELEGATECALL
    evmc_result res{};

    evmc_transfer(msg.sender, msg.destination, msg.value);

    uint64_t nonce = 0;
    eth_account_get_nonce(*(eth_address *)&msg.sender, nonce);
//    EOSIO_ASSERT(nonce >= 0, "on_call: bad nonce");
    eth_account_set_nonce(*(eth_address *)&msg.sender, nonce+1);

    if (msg.destination == ecrecover_address) {
        EOSIO_ASSERT(msg.input_size == 128, "ecrecover: bad input size!");
        intx::uint256 v = from_big_endian(msg.input_data+32, 32);
        if (v >= 27 && v <= 28) {//use ETH recover_key api
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
            
            auto gas_cost = get_precompiled_contract_gas(type_ecrecover, msg.input_size);
            res = evmc_make_result(EVMC_SUCCESS, msg.gas - gas_cost, (uint8_t *)&hash, 32);
        } else {//use EOS recover_key api
            uint8_t hash[32];
            uint8_t sign[66];
            const uint8_t *hashed_message = msg.input_data;

            sign[0] = 0x00; //K1
            sign[1] = uint8_t(v);
            memcpy(sign+2, msg.input_data+64, 64);
            uint8_t pub_key[34];
            int pub_key_size = ::recover_key((checksum256*)hashed_message, (const char *)sign, 66, (char *)pub_key, 34);
            EOSIO_ASSERT(pub_key_size==34, "bad pub key size");
//            printhex(pub_key, 34);prints("\n");
            auto hash256 = ethash::keccak256(pub_key+1, 33);

            memset(hash, 0, 32);
            memcpy(hash+12, (char*)&hash256 + 12, 20);
            auto gas_cost = get_precompiled_contract_gas(type_ecrecover, msg.input_size);
            res = evmc_make_result(EVMC_SUCCESS, msg.gas - gas_cost, (uint8_t *)&hash, 32);
        }
        // bytes32 *r = (bytes32*)msg.input_data + 2;
        // bytes32 *s = (bytes32*)msg.input_data + 3;
        return result(res);
    } else if (msg.destination == sha256_address) {
        struct checksum256 hash{};
        sha256((char *)msg.input_data, (uint32_t)msg.input_size, &hash);
        //vmelog("++++++++++call sha256, input: %s\n", msg.input_data);
        auto gas_cost = get_precompiled_contract_gas(type_sha256, msg.input_size);
        res = evmc_make_result(EVMC_SUCCESS, msg.gas - gas_cost, (uint8_t *)&hash, 32);
        return result(res);
    } else if (msg.destination == ripemd160_address) {
        uint8_t hash[32];
        memset(hash, 0, 32);
        ripemd160((char *)msg.input_data, (uint32_t)msg.input_size, (struct checksum160*)&hash[12]);

        auto gas_cost = get_precompiled_contract_gas(type_ripemd160, msg.input_size);
        res = evmc_make_result(EVMC_SUCCESS, msg.gas - gas_cost, hash, 32);
        return result(res);
    } else if (msg.destination == identity_address) {
        auto gas_cost = get_precompiled_contract_gas(type_identity, msg.input_size);
        res = evmc_make_result(EVMC_SUCCESS, msg.gas - gas_cost, msg.input_data, msg.input_size);
        return result(res);
    } else {
        vector<uint8_t> code;
        eth_account_get_code(*(eth_address*)&msg.destination, code);
        if (code.size()) {
            auto host = EVMHost(origin, version);
            auto evm = evmc::VM{evmc_create_evmone()};
            auto ret = evm.execute(host, version, msg, code.data(), code.size());
            logs = host.get_logs();
            //vmelog("++++++++gas left %d\n", ret.gas_left);
            return ret;
        } else {
            res = evmc_make_result(EVMC_SUCCESS, 0, nullptr, 0);
            return result(res);
        }
    }
}

result on_create(evmc_revision version, evmc_address& origin, const evmc_message& msg, const uint8_t* code, uint32_t code_size, vector<evm_log> &logs, evmc_address& new_address) {
    uint64_t nonce = 0;
    eth_account_get_nonce(*(eth_address *)&msg.sender, nonce);
//    EOSIO_ASSERT(nonce >= 0, "on_create:bad nonce!");

    rlp::ByteString addr;
    addr.resize(20);
    memcpy(addr.data(), msg.sender.bytes, 20);
    auto encoded = rlp::encode(addr, nonce);
    auto hash = ethash::keccak256(encoded.data(), encoded.size());
    memcpy(new_address.bytes, (char*)&hash+12, 20);

    nonce += 1;
    eth_account_set_nonce(*(eth_address *)&msg.sender, nonce);

    uint64_t creator = eth_account_find_creator_by_address(*(eth_address *)&msg.sender);
    eth_account_create(*(eth_address *)&new_address, creator);

    evmc_message msg_creation = msg;
    msg_creation.destination = new_address;
 
    evmc_transfer(msg_creation.sender, msg_creation.destination, msg.value);

    auto host = EVMHost(origin, version);
    auto evm = evmc::VM{evmc_create_evmone()};
    auto res = evm.execute(host, version, msg_creation, code, code_size);
    if (res.status_code != EVMC_SUCCESS) {
        EOSIO_THROW(get_status_error(res.status_code));
    }
    vector<uint8_t> _code(res.output_data, res.output_data + res.output_size);
    eth_account_set_code(*(eth_address*)&new_address, _code);
    logs = host.get_logs();
    return res;
}
