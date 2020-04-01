#include <eosio/print.hpp>
#include <eosio/name.hpp>
#include <eosio/action.hpp>
#include <eosio/asset.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/singleton.hpp>
#include <eosio/fixed_bytes.hpp>
#include "eth_account.hpp"
#include "table_struct.hpp"
#include "evm_test.hpp"

using namespace eosio;
using namespace std;

#define MAIN_TOKEN_NAME "EOS"


extern "C" 
{

#if defined USE_INTRINSIC_EVM_EXECUTE
    __attribute__((eosio_wasm_import))
    int evm_execute(const char *raw_trx, uint32_t raw_trx_size, const char *sender_address, uint32_t sender_address_size);
#else
    EVM_API int evm_execute(const char *raw_trx, uint32_t raw_trx_size, const char *sender_address, uint32_t sender_address_size);
#endif
}

#if defined USE_INTRINSIC_EVM_GET_ACCOUNT_ID
    __attribute__((eosio_wasm_import))
    extern "C" int evm_get_account_id(uint64_t account, const char* arbitrary_string, size_t arbitrary_string_size, char* hash, size_t hash_size);
#else
    extern "C" EVM_API int evm_get_account_id(const char* account, size_t account_size, const char* arbitrary_string, size_t arbitrary_string_size, char* hash, size_t hash_size);

    int evm_get_account_id(uint64_t account, const char* arbitrary_string, size_t arbitrary_string_size, char* hash, size_t hash_size) {
        string _account = name(account).to_string();
        return ::evm_get_account_id(_account.c_str(), _account.size(), arbitrary_string, arbitrary_string_size, hash, hash_size);
    }
#endif

template<typename T>
T unpack_args() {
    size_t raw_args_size = action_data_size();
    check(raw_args_size > 0, "bad args");
    vector<char> raw_args(raw_args_size);
    read_action_data(raw_args.data(), raw_args_size);
    T rec = eosio::unpack<T>(raw_args);
    return rec;
}

struct transfer {
    name from;
    name to;
    asset quantity;
    string memo;
    EOSLIB_SERIALIZE( transfer, (from)(to)(quantity)(memo) )
};

struct addrinfo {
    uint64_t nonce;
    asset balance;
    EOSLIB_SERIALIZE( addrinfo, (nonce)(balance) )
};

struct create {
    name account;
    string text;
    EOSLIB_SERIALIZE( create, (account)(text) )
};

struct withdraw {
    name account;
    asset amount;
    EOSLIB_SERIALIZE( withdraw, (account)(amount) )
};

struct raw {
    vector<char> trx;
    vector<char> sender;
    EOSLIB_SERIALIZE( raw, (trx)(sender) )
};

struct bind_address {
    name         account;
    eth_address  address;
    EOSLIB_SERIALIZE( bind_address, (account)(address) )
};

extern "C" {
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
        check(secp256k1_ecmult_static_context != nullptr, "secp256k1_ecmult_static_context not initialized!");
        return secp256k1_ecmult_static_context;
    }

    void apply( uint64_t receiver, uint64_t code, uint64_t action ) {
        name _self(receiver);
        if (receiver == code) {
#ifndef USE_INTRINSIC_EVM_RECOVER_KEY
            if (action == "init"_n.value) {
                init_secp256k1_ecmult_static_context(current_receiver().value);
                return;
            }
#endif
            if (action == "create"_n.value) {
                eth_address address;
                auto v = unpack_action_data<create>();
                require_auth(v.account);
                evm_get_account_id(v.account.value, v.text.c_str(), v.text.size(), (char *)address.data(), 20);
                eosio::printhex(address.data(), address.size());
                eth_account_bind_address_to_creator(address, v.account.value);
                bool ret = eth_account_create(address, v.account.value);
            } else if (action == "bind"_n.value) {
                eth_address address;
                auto v = unpack_action_data<bind_address>();
                eth_account_bind_address_to_creator(v.address, v.account.value);
                bool ret = eth_account_create(v.address, v.account.value);
            } else if (action == "raw"_n.value) {
                auto a = unpack_action_data<raw>();
                evm_execute(a.trx.data(), a.trx.size(), a.sender.data(), a.sender.size());
            } else if (action == "getaddrinfo"_n.value) {
                eth_address address;
                int64_t nonce;
                int64_t ram_quota;
                eth_uint256 amount;
                
                auto v = unpack_action_data<vector<char>>();
                check(v.size() == 20, "bad address");
                memcpy(address.data(), v.data(), address.size());
                
                uint64_t creator = 0;
                uint64_t index = eth_account_get_info(address, &creator, &nonce, &amount);
                check(creator > 0, "eth address not found!");
                
                addrinfo info;
                info.nonce = nonce;
                info.balance.amount = *(int64_t*)&amount;
                info.balance.symbol = symbol(ETH_ASSET_SYMBOL, 4);
                auto packed_info = eosio::pack<addrinfo>(info);
                printhex(packed_info.data(), packed_info.size());
            } else if (action == "withdraw"_n.value) {
                auto v = unpack_action_data<withdraw>();
                require_auth(v.account);
                check(v.amount.amount > 0, "bad withdraw value");
                
                eth_address address;
                bool ret = eth_account_find_address_by_binded_creator(v.account.value, address);
                check(ret, "eth address not found!");
{
                asset a(0, symbol(ETH_ASSET_SYMBOL, 4));
                eth_uint256 _balance = eth_account_get_balance(address);
                uint128_t& balance = *(uint128_t*)&_balance;
                check(balance <= (uint128_t)max_amount, "balance overflow!");

                a.amount = (int64_t)balance;
//                eosio::print(a.symbol, v.amount.symbol);
                check(a.amount >= v.amount.amount, "balance overdraw!");
                a -= v.amount;

                eth_uint256 amount{};
                memcpy(amount.bytes, &a.amount, sizeof(a.amount));

                eth_account_set_balance(address, amount, same_payer.value);
}
                struct action a;
                a.account = "eosio.token"_n;
                a.name = "transfer"_n;
                a.authorization.push_back({name(receiver), "active"_n});


                transfer t;
                t.from = name(receiver);
                t.to = v.account;
                t.quantity.amount = v.amount.amount;
                t.quantity.symbol = symbol(MAIN_TOKEN_NAME, 4);
                t.memo = "withdraw";
                a.data = eosio::pack<transfer>(t);
                a.send();
            } else if (action == "setchainid"_n.value) {
                int32_t chain_id = unpack_action_data<int32_t>();
                eth_set_chain_id(chain_id);
            }
        } else {
            if (action != "transfer"_n.value) {
                return; 
            }
            
            if (name(code) == "eosio.token"_n && name(action) == "transfer"_n) {
                auto t = unpack_action_data<transfer>();
                if (t.to == _self && t.quantity.symbol == symbol(MAIN_TOKEN_NAME, 4) && t.memo == "deposit") {
                    eth_address address;
                    bool ret = eth_account_find_address_by_binded_creator(t.from.value, address);
                    check(ret, "eth address not bind to an EOS account!");
                    asset a(0, symbol(MAIN_TOKEN_NAME, 4));

                    check(t.quantity.amount > 0, "bad transfer value!");
                    eth_uint256 _balance = eth_account_get_balance(address);
                    uint128_t& balance = *(uint128_t*)&_balance;
                    check(balance <= (uint128_t)max_amount, "balance overflow!");
                    a.amount = (int64_t)balance;
                    // eosio::print("+++++eth amount:", a.amount);
                    a += t.quantity;

                    eth_uint256 amount{};
                    memcpy(amount.bytes, &a.amount, sizeof(a.amount));
                    eth_account_set_balance(address, amount, same_payer.value);
                }
            }
        }
    }
}
