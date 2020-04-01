#pragma once
#include <eosio/asset.hpp>
#include <eosio/eosio.hpp>
#include <eosio/fixed_bytes.hpp>

#include <eosio/system.hpp>
#include <vector>

using namespace std;
using namespace eosio;

#define SIZE_256BIT 32
#define SIZE_ADDRESS 20

typedef unsigned __int128 uint128_t;

struct evm_storage {
    vector<uint8_t> key;
    vector<uint8_t> value;    
    EOSLIB_SERIALIZE( evm_storage, (key)(value) )
};

struct address_info {
    eth_address             address;
    uint64_t                nonce;
    std::array<uint8_t, 32> balance;
    vector<uint8_t>        code;
    vector<std::array<uint8_t, 32>> storage;
    EOSLIB_SERIALIZE( address_info, (address)(nonce)(balance)(code)(storage) )
};

struct testenv {
    vector<uint8_t>     current_coinbase;
    uint64_t            current_difficulty;
    uint64_t            current_gas_limit;
    uint64_t            current_number;
    uint64_t            current_timestamp;

    EOSLIB_SERIALIZE( testenv, (current_coinbase)(current_difficulty)(current_gas_limit)(current_number)(current_timestamp) )
};

struct testexec {
    // "address" : "0x0f572e5295c57f15886f9b263e2f6d2d6c7b5ec6",
    // "caller" : "0xcd1722f3947def4cf144679da39c4c32bdc35681",
    // "code" : "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7feeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee16600055",
    // "data" : "0x",
    // "gas" : "0x0186a0",
    // "gasPrice" : "0x5af3107a4000",
    // "origin" : "0xcd1722f3947def4cf144679da39c4c32bdc35681",
    // "value" : "0x0de0b6b3a7640000"
    eth_address address;
    eth_address caller;
    vector<uint8_t> code;
    vector<uint8_t> data;
    uint64_t gas;
    uint64_t gas_price;
    eth_address origin;
    std::array<uint8_t, 32> value;
    EOSLIB_SERIALIZE( testexec, (address)(caller)(code)(data)(gas)(gas_price)(origin)(value) )
};

struct [[eosio::table]] ethaccount {
    uint64_t                        index;
    uint64_t                        creator;
    int64_t                         nonce;
    eth_address                     address;
    std::array<uint8_t, 32>         balance;
    uint64_t primary_key() const { return index; }

    checksum256 by_address() const {
       auto ret = checksum256();
       memcpy(ret.data(), address.data(), SIZE_ADDRESS);
       return ret;
    }

    uint64_t by_creator() const {
        return creator;
    }

    EOSLIB_SERIALIZE( ethaccount, (index)(creator)(nonce)(address)(balance) )
};

struct [[eosio::table]] account_state {
    uint64_t                        index;
    vector<char>                    key;
    vector<char>                    value;

    account_state() {
        key.resize(32);
        value.resize(32);
    }

    uint64_t primary_key() const { return index; }

    checksum256 by_key() const {
        auto ret = checksum256();
        check(key.size() == 32, "bad key size!");
        memcpy(ret.data(), key.data(), 32);
        return ret;
    }

    EOSLIB_SERIALIZE( account_state, (index)(key)(value) )
};

struct [[eosio::table]] ethcode {
    uint64_t                        index;
    eth_address                     address;
    vector<char>                    code;
    uint64_t                        version;
    uint64_t primary_key() const { return index; }

    checksum256 by_address() const {
       auto ret = checksum256();
       memcpy(ret.data(), address.data(), SIZE_ADDRESS);
       return ret;
    }

    EOSLIB_SERIALIZE( ethcode, (index)(address)(code)(version) )
};

struct [[eosio::table]] accountcounter {
    uint64_t                        count;
    int32_t                         chain_id;
    EOSLIB_SERIALIZE( accountcounter, (count)(chain_id) )
};

/*
This struct used to map 256 bit key to 64 bit primary key, 
there's no need to worry about the counter overflow, 
the reason is:
let's suppose we can do one store/delete operation in 1us,
that means we can do 1,000,000 operations in 1s,
and it need about 584942.4(0xffffffffffffffff/1000000/60/60/24/365) years to overflow the counter
that's safe enough
*/
struct [[eosio::table]] key256counter {
    uint64_t                        count;
    EOSLIB_SERIALIZE( key256counter, (count) )
};

struct [[eosio::table]] addressmap {
    uint64_t            creator;
    eth_address         address;
    uint64_t primary_key() const { return creator; }
    checksum256 by_address() const {
       auto ret = checksum256();
       memcpy(ret.data(), address.data(), SIZE_ADDRESS);
       return ret;
    }
    EOSLIB_SERIALIZE( addressmap, (creator)(address) )
};

typedef multi_index<"addressmap"_n,
                    addressmap,
                    indexed_by< "byaddress"_n, const_mem_fun<addressmap, checksum256, &addressmap::by_address> >
                > addressmap_table;

typedef eosio::singleton< "global"_n, accountcounter >   account_counter;
typedef eosio::singleton< "global2"_n, key256counter >   key256_counter;


typedef multi_index<"ethaccount"_n,
                ethaccount,
                indexed_by< "byaddress"_n, const_mem_fun<ethaccount, checksum256, &ethaccount::by_address> >,
                indexed_by< "bycreator"_n, const_mem_fun<ethaccount, uint64_t, &ethaccount::by_creator> > 
                > ethaccount_table;

typedef multi_index<"accountstate"_n,
                account_state,
                indexed_by< "bykey"_n,
                const_mem_fun<account_state, checksum256, &account_state::by_key> > > account_state_table;


typedef multi_index<"ethcode"_n, ethcode> ethcode_table;
