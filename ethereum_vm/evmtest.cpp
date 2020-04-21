#include <eosio/print.hpp>
#include <eosio/name.hpp>
#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/singleton.hpp>
#include <eosio/fixed_bytes.hpp>
#include "eth_account.hpp"
#include "table_struct.hpp"

using namespace std;
using namespace eosio;


struct raw {
    vector<char> trx;
    vector<char> sender;
    EOSLIB_SERIALIZE( raw, (trx)(sender) )
};

/*
"currentCoinbase" : "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
"currentDifficulty" : "0x0100",
"currentGasLimit" : "0x0f4240",
"currentNumber" : "0x00",
"currentTimestamp" : "0x01"


{'0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6': {
    'balance': '0x152d02c7e14af6800000',
    'code': '0x6000600020600055',
    'nonce': '0x00',
    'storage': {}
    }
}
*/

extern "C" {
    void evm_execute_test(const uint8_t* tests, uint32_t _size);

#ifdef USE_INTRINSIC_EVM_EXECUTE
    __attribute__((eosio_wasm_import))
#endif
    int evm_execute(const char *raw_trx, uint32_t raw_trx_size, const char *sender_address, uint32_t sender_address_size);


    #define CONTEXT_SIZE (64*1024)
    #define WASM_IMPORT __attribute__((eosio_wasm_import))

    WASM_IMPORT int32_t db_store_i64(uint64_t scope, uint64_t table, uint64_t payer, uint64_t id,  const void* data, uint32_t len);
    WASM_IMPORT void db_update_i64(int32_t iterator, uint64_t payer, const void* data, uint32_t len);
    WASM_IMPORT int32_t db_get_i64(int32_t iterator, const void* data, uint32_t len);
    WASM_IMPORT int32_t db_find_i64(uint64_t code, uint64_t scope, uint64_t table, uint64_t id);

    // WASM_IMPORT uint32_t read_action_data( void* msg, uint32_t len );
    // WASM_IMPORT uint32_t action_data_size(void);

    static char *secp256k1_ecmult_static_context = nullptr;

    void init_secp256k1_ecmult_static_context(uint64_t payer) {
        uint32_t size = action_data_size();
        check(size==CONTEXT_SIZE, "bad secp256k1_ecmult_static_context size");
        secp256k1_ecmult_static_context = (char *)malloc(size);
        read_action_data(secp256k1_ecmult_static_context, size);
        auto itr = db_find_i64(current_receiver().value, "ecmult"_n.value, "static"_n.value, "context"_n.value);
        if (itr < 0) {
            db_store_i64("ecmult"_n.value, "static"_n.value, payer, "context"_n.value, secp256k1_ecmult_static_context, size);
        } else {
            db_update_i64(itr, payer, secp256k1_ecmult_static_context, size);
        }
    }

    void load_secp256k1_ecmult_static_context() {
        if (secp256k1_ecmult_static_context) {
            return;
        }
        auto itr = db_find_i64(current_receiver().value, "ecmult"_n.value, "static"_n.value, "context"_n.value);
        check(itr >= 0, "secp256k1_ecmult_static_context not found in db");
        secp256k1_ecmult_static_context = (char *)malloc(CONTEXT_SIZE);
        int size = ::db_get_i64(itr, secp256k1_ecmult_static_context, CONTEXT_SIZE);
        check(size == CONTEXT_SIZE, "bad secp256k1_ecmult_static_context data");
    }

    void* get_secp256k1_ecmult_static_context() {
        load_secp256k1_ecmult_static_context();
        check(secp256k1_ecmult_static_context != nullptr, "secp256k1_ecmult_static_context not initialized!");
        return secp256k1_ecmult_static_context;
    }



    void apply(uint64_t receiver, uint64_t code, uint64_t action) {
        if (action == "clearenv"_n.value) {
            eth_account_clear_all();
        } else if (action == "setaddrinfo"_n.value) {
            auto info = unpack_action_data<address_info>();
            eth_account_create(info.address, code);
            eth_account_set_nonce(info.address, info.nonce);
            // printhex(info.balance.data(), info.balance.size());print("\n");
            eosio::check(info.balance.size()==32, "bad balance value!!");
            eth_account_set_balance(info.address, *(eth_uint256*)info.balance.data(), receiver);
            eth_account_set_code(info.address, info.code);
            for (uint32_t i=0;i<info.storage.size();i+=2) {
                auto& key = info.storage[i*2];
                auto& value = info.storage[i*2+1];
                // printhex(key.data(), key.size());print(":");printhex(value.data(), value.size());
                eth_account_set_value(info.address, key, value);
            }
        } else if (action == "raw"_n.value) {
            auto a = unpack_action_data<raw>();
            #ifdef USE_INTRINSIC_EVM_EXECUTE
                evm_execute(a.trx.data(), a.trx.size(), a.sender.data(), a.sender.size());
            #else
                evm_execute_test((uint8_t*)a.trx.data(), a.trx.size());
            #endif
        } else if (action == "raw2"_n.value) {
            auto a = unpack_action_data<raw>();
            evm_execute(a.trx.data(), a.trx.size(), a.sender.data(), a.sender.size());
        } else if (action == "clearenv"_n.value) {
            eth_account_clear_all();
        }
    }
}
