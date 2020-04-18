
#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmone/evmone.h>
#include "execution.hpp"
#include "../test/utils/utils.hpp"

#include "eevm/rlp.h"

#include <eth_account.hpp>
#include <evm_test.hpp>

#include <ethash/keccak.hpp>

#include <eosiolib_legacy/eosiolib.h>

#include "evmhost.hpp"

// #define EVMC_VERSION EVMC_FRONTIER
// #define EVMC_VERSION EVMC_HOMESTEAD
// #define EVMC_VERSION EVMC_BYZANTIUM
#define EVMC_VERSION EVMC_ISTANBUL

void evmc_transfer(const evmc_address& sender, const evmc_address& receiver, const evmc_uint256be& value) {

    uint256_t amount = from_big_endian(value.bytes, 32);
    uint64_t creator = eth_account_find_creator_by_address(ETH_ADDRESS(sender));

    // EOSIO_ASSERT(amount <= max_amount && amount >= 0, "call:bad transfer value");
    if (amount == 0) {
        return;
    }

    eth_uint256 _sender_amount = eth_account_get_balance(*(eth_address*)&sender);
    eth_uint256 _receiver_amount = eth_account_get_balance(*(eth_address*)&receiver);
    uint256_t& sender_amount = *(uint256_t*)&_sender_amount;
    uint256_t& receiver_amount = *(uint256_t*)&_receiver_amount;
    EOSIO_ASSERT(sender_amount >= amount, "call:overdraw balance!");
    sender_amount -= amount;
    receiver_amount += amount;
    if (receiver_amount < amount) {
        EOSIO_THROW("receiver amount overflow!");
    }

    eth_account_set_balance(*(eth_address*)&sender, _sender_amount, creator);
    eth_account_set_balance(*(eth_address*)&receiver, _receiver_amount, 0);
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

#define EIP155_CHAIN_ID_OFFSET  (35)

bool is_eip_155_signed_transaction(uint32_t v) {
    if (v >= EIP155_CHAIN_ID_OFFSET) {
        return true;
    }
    return false;
}

bool is_even(uint32_t v) {
    return v % 2 == 0;
}

int evm_execute_trx(const uint8_t *raw_trx, uint32_t raw_trx_size, const char *sender_address, uint32_t sender_address_size) {
//    EOSIO_ASSERT(sender_address_size == 20, "bad sender size");
    auto decoded_trx = rlp::decode<uint256_t, uint256_t, uint256_t, rlp::ByteString, rlp::ByteString, rlp::ByteString, rlp::ByteString, uint256_t, uint256_t>(raw_trx, (size_t)raw_trx_size);
    // std::cout << (uint64_t)std::get<0>(decoded_trx) << std::endl; //nonce
    // std::cout << (uint64_t)std::get<1>(decoded_trx) << std::endl; //gas_price
    // std::cout << (uint64_t)std::get<2>(decoded_trx) << std::endl; //gas_limit

    int32_t chain_id = 0;
    auto msg = evmc_message{};
    msg.gas = max_gas_limit;

//        std::cout << (uint64_t)std::get<3>(decoded_trx) << std::endl; //to
    
    auto value = std::get<4>(decoded_trx); //value
    //value is big endian encoded
    msg.value = to_balance(value.data(), (uint32_t)value.size());

    // std::cout << (uint64_t)std::get<5>(decoded_trx) << std::endl; // data
    rlp::ByteString _v = std::get<6>(decoded_trx); //v
    uint32_t v = big_endian_to_uint32(_v.data(), (uint32_t)_v.size());

    auto r = std::get<7>(decoded_trx); //r
    auto s = std::get<8>(decoded_trx); //s

    // EOSIO_ASSERT(r.size() == 32 || r.size() == 0, "bad signature size");
    // EOSIO_ASSERT(s.size() == 32 || s.size() == 0, "bad signature size");




    if (r == 0 && s == 0) {
        EOSIO_ASSERT(sender_address_size == 20, "evm_execute:bad sender size!");
        memcpy(msg.sender.bytes, sender_address, 20);
        eth_account_check_address(*(eth_address*)&msg.sender);
        uint64_t creator = eth_account_find_creator_by_address(ETH_ADDRESS(msg.sender));
        require_auth(creator);
        chain_id = (int32_t)v;
        check_chain_id(chain_id);
    } else {
        if (v > 36) {
            chain_id = (v - 35) / 2; //v = chain_id *2 + 35
        } else if (v == 27 || v == 28) {
            chain_id = -4;
        }
        else {
            EOSIO_THROW("invalid signature!");
        }

        if (chain_id != -4 && (0xff800000 & uint32_t(chain_id)) != 0) {//sign with eos private key
            uint8_t first_byte = uint32_t(chain_id) >> 24; //first byte of eos signature
            chain_id = uint32_t(chain_id) & 0x7fffff;
            check_chain_id(chain_id);
            uint8_t sign[66];
            sign[0] = 0x00; //K1
            sign[1] = first_byte;

            r = from_big_endian((uint8_t*)&r);
            s = from_big_endian((uint8_t*)&s);

            memcpy(sign+2, &r, 32);
            memcpy(sign+2+32, &s, 32);
            uint8_t pub_key[34];

            rlp::ByteString unsigned_trx = rlp::encode(std::get<0>(decoded_trx), std::get<1>(decoded_trx),std::get<2>(decoded_trx),std::get<3>(decoded_trx),std::get<4>(decoded_trx),std::get<5>(decoded_trx));
            auto hash256  = ethash::keccak256(unsigned_trx.data(), unsigned_trx.size());
            int pub_key_size = ::recover_key((checksum256*)hash256.bytes, (const char *)sign, 66, (char *)pub_key, 34);
            EOSIO_ASSERT(pub_key_size==34, "bad pub key size");
//            printhex(pub_key, 34);prints("\n");

            EOSIO_ASSERT(sender_address_size == 20, "evm_execute:bad sender size!");
            uint64_t creator = eth_account_find_creator_by_address(*(eth_address*)sender_address);
            string _name = n2s(creator);
            string _pub_key = to_hex(pub_key+1, 33);

            auto id = rlp::encode(_name, _pub_key);
            hash256 = ethash::keccak256(id.data(), id.size());
            memcpy(msg.sender.bytes, hash256.bytes + 12, 20);
            EOSIO_ASSERT(msg.sender == *(evmc_address*)sender_address, "eth_address not the same");
//            printhex(hash256.bytes, 32);prints("\n");
        } else {//sign with eth private key
            check_chain_id(chain_id);
            uint8_t sig[65];
            r = from_big_endian((uint8_t*)&r);
            s = from_big_endian((uint8_t*)&s);
            memcpy(sig, &r, 32);
            memcpy(sig+32, &s, 32);
            if (is_eip_155_signed_transaction(v)) {
                if (is_even(v)) {
                    v = 28;
                } else {
                    v = 27;
                }
            }
            v -= 27;
            sig[64] = uint8_t(v);

            rlp::ByteString unsigned_trx;
            if (chain_id == -4) {
                unsigned_trx = rlp::encode(std::get<0>(decoded_trx), std::get<1>(decoded_trx),std::get<2>(decoded_trx),std::get<3>(decoded_trx),std::get<4>(decoded_trx),std::get<5>(decoded_trx));
            } else {
                unsigned_trx = rlp::encode(std::get<0>(decoded_trx), std::get<1>(decoded_trx),std::get<2>(decoded_trx),std::get<3>(decoded_trx),std::get<4>(decoded_trx),std::get<5>(decoded_trx), chain_id, "", "");
            }

            auto hash256 = ethash::keccak256(unsigned_trx.data(), unsigned_trx.size());
            uint8_t pub_key[65];
            memset(pub_key, 0, 65);
            evm_recover_key(sig, 65, (uint8_t *)&hash256, 32, pub_key, 65);
            auto addr = ethash::keccak256(pub_key+1, 64);
            memcpy(msg.sender.bytes, addr.bytes + 12, 20);
        }
        eth_account_check_address(*(eth_address*)&msg.sender);
    }

    uint64_t nonce = 0;
    bool ret = eth_account_get_nonce(*(eth_address *)&msg.sender, nonce);
    EOSIO_ASSERT(ret, "get_nonce: bad nonce");
    EOSIO_ASSERT(std::get<0>(decoded_trx) == nonce, "Invalid nonce");

    auto address = std::get<3>(decoded_trx);
    if (address.size() == 0) {//receiver addres is empty, it's a Creation transaction
        msg.kind = EVMC_CREATE;
    } else {
        msg.kind = EVMC_CALL;
        EOSIO_ASSERT(address.size() == 20, "bad destination address");
        eth_account_check_address(*(eth_address*)address.data());
        memcpy(msg.destination.bytes, address.data(), 20);
    }
    //vmelog("+++++++++++++++msg.kind %d\n", msg.kind);
    auto data = std::get<5>(decoded_trx);



    if (msg.kind == EVMC_CREATE) {
        // msg.input_data = data.data();
        // msg.input_size = data.size();
        vector<evm_log> logs;
        evmc_address new_address;
        result res = on_create(EVMC_VERSION, msg.sender, msg, data.data(), (uint32_t)data.size(), logs, new_address);
        print_result(new_address, res.output_data, res.output_size, logs, res.gas_left);
        if (res.status_code != EVMC_SUCCESS) {
            EOSIO_THROW(get_status_error(res.status_code));
        }
    } else if (msg.kind == EVMC_CALL) {
        msg.input_data = data.data();
        msg.input_size = data.size();
        vector<evm_log> logs;

        auto res = on_call(EVMC_VERSION, msg.sender, msg, logs);
        print_result(msg.destination, res.output_data, res.output_size, logs, res.gas_left);

        if (res.status_code != EVMC_SUCCESS) {
            EOSIO_THROW(get_status_error(res.status_code));
        }

    } else {
        EOSIO_ASSERT(0, "bad message kind");
    }

    return 1;
}

#ifndef __WASM

//evmone4eosio_test.cpp
extern "C" void evm_execute_test(const uint8_t* tests, uint32_t _size);

extern "C" EVMC_EXPORT int evm_execute(const uint8_t *raw_trx, size_t raw_trx_size, const char *sender_address, size_t sender_address_size) {
    if (memcmp(sender_address+4, "\xff\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf7\xf6\xf5\xf4\xf3\xf2\xf1\xf0", 16)== 0) {
        evm_execute_test(raw_trx, raw_trx_size);
        return 0;
    } else {
        evm_execute_trx(raw_trx, raw_trx_size, sender_address, sender_address_size);
    }
    return 0;
}

#else

#ifndef USE_INTRINSIC_EVM_EXECUTE
extern "C" EVMC_EXPORT int evm_execute(const uint8_t *raw_trx, uint32_t raw_trx_size, const char *sender_address, size_t sender_address_size) {
    evm_execute_trx(raw_trx, raw_trx_size, sender_address, sender_address_size);
    return 0;
}
#endif

#endif


#ifdef __WASM

extern "C" {

#ifdef __WASM
    int __cxa_thread_atexit(void (*func)(), void *obj, void *dso_symbol) {
        EOSIO_THROW("bad call of __cxa_thread_atexit!");
        return 0;
    }
#endif

}
namespace std {
    inline namespace __1 {
        size_t __next_prime(unsigned int a) {
            EOSIO_THROW("bad call of __next_prime!");
            return 0;
        }
    }
}

namespace std {
    bool uncaught_exception() noexcept {
        EOSIO_THROW("bad call of uncaught_exception!");
        return true;
    }
}
#endif
