#include "eth_account.hpp"

#include <eosio/print.hpp>
#include <eosio/name.hpp>
#include <eosio/action.hpp>

#include <eosio/singleton.hpp>

#include "table_struct.hpp"

#ifdef USE_KEY256_VALUE_TABLE
#define VM_API_IMPORT __attribute__((eosio_wasm_import))

extern "C"
{
    VM_API_IMPORT uint32_t db_get_table_count(uint64_t a, uint64_t b, uint64_t c);
    VM_API_IMPORT int32_t db_store_i256( uint64_t scope, uint64_t table, uint64_t payer, void* id, int size, const char* buffer, size_t buffer_size );
    VM_API_IMPORT void db_update_i256( int iterator, uint64_t payer, const char* buffer, size_t buffer_size );
    VM_API_IMPORT void db_remove_i256( int iterator );
    VM_API_IMPORT int32_t db_get_i256( int iterator, char* buffer, size_t buffer_size );
    VM_API_IMPORT int32_t db_find_i256( uint64_t code, uint64_t scope, uint64_t table, void* id, size_t size );
    VM_API_IMPORT int db_previous_i256( int itr, void* primary, size_t id_size );
    VM_API_IMPORT int db_next_i256( int itr, void* primary, size_t id_size );
    VM_API_IMPORT int db_lowerbound_i256( uint64_t code, uint64_t scope, uint64_t table, void* id, size_t id_size );
    VM_API_IMPORT int db_upperbound_i256( uint64_t code, uint64_t scope, uint64_t table, void* id, size_t id_size );
}

#endif

uint64_t get_next_key256_index(uint64_t payer) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    key256_counter counter(name(code), scope);

    key256counter a = {0};
    a = counter.get_or_default(a);
    a.count += 1;
    counter.set(a, name(payer));
    return a.count;
}

uint64_t get_next_eth_address_index(uint64_t payer) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    account_counter counter(name(code), scope);
    accountcounter a = {};
    a = counter.get_or_default(a);
    a.count += 1;
    counter.set(a, name(payer));
    return a.count;
}

void eth_set_chain_id(int32_t chain_id) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    uint64_t payer = current_receiver().value;

    account_counter counter(name(code), scope);

    accountcounter a = {};
    a = counter.get_or_default(a);
    a.chain_id = chain_id;
    counter.set(a, name(payer));
}

int32_t eth_get_chain_id() {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    account_counter counter(name(code), scope);

    accountcounter a = {};
    a = counter.get_or_default(a);
    return a.chain_id;
}

bool eth_account_bind_address_to_creator(eth_address& address, uint64_t creator) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    name payer(creator);

    addressmap_table table(name(code), scope);
    check (table.end() == table.find(creator), "eth address already bind to an EOS account");

    table.emplace( payer, [&]( auto& row ) {
        row.creator = creator;
        row.address = address;
    });
    return true;
}

bool eth_account_find_address_by_binded_creator(uint64_t creator, eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    name payer(creator);

    addressmap_table table(name(code), scope);
    auto itr = table.find(creator);
    check (table.end() != itr, "creator does not bind to an eth address");
    address = itr->address;
    return true;
}

uint64_t eth_account_find_creator_by_address(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return 0;
    }
    return itr->creator;
}

uint64_t eth_account_find_index_by_address(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return 0;
    }
    return itr->index;
}

bool eth_account_find_creator_and_index_by_address(eth_address& address, uint64_t& creator, uint64_t& index) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return false;
    }
    creator = itr->creator;
    index = itr->index;
    return true;
}

bool eth_account_create(eth_address& address, uint64_t creator, uint64_t nonce) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    uint64_t payer = creator;

    require_auth(name(creator));

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    // eosio::print("\n", creator, "\n");
    // eosio::printhex(address.data(), address.size());
    
    auto itr2 = idx_sec.find(_address);
    if (itr2 == idx_sec.end()) {
        uint64_t index = get_next_eth_address_index(creator);
        // eosio::print("address not found!\n");
        mytable.emplace( name(payer), [&]( auto& row ) {
            row.balance = {};
            row.address = address;
            row.index = index;
            row.creator = creator;
            row.nonce = nonce;
        });
        return true;
    } else {
        eosio::check(false, "eth address already exists!!!");
    }
    return false;
}

bool eth_account_exists(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();
    
    auto idx = idx_sec.find(_address);
    if (idx == idx_sec.end()) {
        return false;
    }
    return true;
}

void eth_account_check_address(eth_address& address) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

//    eosio::printhex(address.data(), address.size());

    auto idx = idx_sec.find(_address);
    check(idx != idx_sec.end(), "eth address does not exists!");
}

uint64_t eth_account_get_info(eth_address& address, uint64_t* creator, int64_t* nonce, eth_uint256* amount) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto idx = idx_sec.find(_address);
    if (idx == idx_sec.end()) {
        return 0;
    }
    if (nonce) {
        *nonce = idx->nonce;
    }
    if (amount) {
#ifdef EVM_FOR_PASS_VMTESTS
        memcpy(amount->bytes, idx->balance.data(), 32);
#else
        *((int64_t*)&amount) = idx->balance.amount;
#endif
    }
    if (creator) {
        *creator = idx->creator;
    }
    return idx->index;;
}

bool eth_account_get(eth_address& address, ethaccount& account) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        return false;
    }
    account = *itr;
    return true;
}

bool eth_account_set(eth_address& address, const ethaccount& account) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    uint64_t payer = current_receiver().value;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    account_counter counter(name(code), scope);
    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);
    if (itr == idx_sec.end()) {
        eosio::check(false, "eth_account_set: account does not exists!");
        return false;
    }
    auto itr2 = mytable.find(itr->index);
    mytable.modify( itr2, name(payer), [&]( auto& row ) {
        row = account;
    });
    return true;
}

eth_uint256 eth_account_get_balance(eth_address& address) {
    eth_uint256 balance{};
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable(name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);
//    check(itr != idx_sec.end(), "get_balance:address does not created!");
    if (itr != idx_sec.end()) {
#ifdef EVM_FOR_PASS_VMTESTS
        balance = *(eth_uint256*)&itr->balance;
#else
        *((int64_t*)&balance) = itr->balance.amount;
#endif
    }
    return balance;
}

bool eth_account_set_balance(eth_address& address, eth_uint256& amount, uint64_t payer) {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethaccount_table mytable( name(code), scope);
    auto idx_sec = mytable.get_index<"byaddress"_n>();

    auto itr = idx_sec.find(_address);

#ifdef EVM_FOR_PASS_VMTESTS
    if (itr == idx_sec.end()) {
        eth_account_create(address, code, 0);
        itr = idx_sec.find(_address);
    }
#else
    check(itr != idx_sec.end(), "set_balance:address does not created");
#endif
    auto itr2 = mytable.find(itr->index);
    mytable.modify( itr2, name(0), [&]( auto& row ) {
#ifdef EVM_FOR_PASS_VMTESTS
        memcpy(row.balance.data(), amount.bytes, 32);
#else
        row.balance.amount = ((int64_t*)&amount)[0];
        row.balance.symbol = symbol(ETH_ASSET_SYMBOL, 4);
#endif
    });
    return true;
}

bool eth_account_get_code(eth_address& address, std::vector<unsigned char>& evm_code) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    if (!ret) {
        return false;
    }

//    check(creator, "get_code: address creator not found!");
    
    uint64_t code = current_receiver().value;

    ethcode_table mytable(name(code), creator);
    auto itr = mytable.find(address_index);
    if (itr == mytable.end()) {
        return false;
    }

    evm_code.resize(itr->code.size());
    memcpy(evm_code.data(), itr->code.data(), evm_code.size());
    return true;
}

bool eth_account_set_code(eth_address& address, const std::vector<unsigned char>& evm_code) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_code: address not created!");

    require_auth(name(creator));
    
    uint64_t code = current_receiver().value;


    ethcode_table mytable(name(code), creator);
    auto itr = mytable.find(address_index);
    if (itr == mytable.end()) {
        mytable.emplace( name(creator), [&]( auto& row ) {
            row.index = address_index;
            row.address = address;
            row.code.resize(evm_code.size());
            memcpy(row.code.data(), evm_code.data(), evm_code.size());
        });
    } else {
        check(false, "can not modify evm code!");
        mytable.modify( itr, name(creator), [&]( auto& row ) {
            row.code.resize(evm_code.size());
            memcpy(row.code.data(), evm_code.data(), evm_code.size());
        });
    }

    return true;
}

uint32_t  eth_account_get_code_size(eth_address& address) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    if (!ret) {
        return false;
    }

//    check(creator, "get_code: address creator not found!");
    
    uint64_t code = current_receiver().value;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    ethcode_table mytable(name(code), creator);
    auto itr = mytable.find(address_index);
    if (itr == mytable.end()) {
        return 0;
    }
    return itr->code.size();
}

bool eth_account_clear_code(eth_address& address) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_code: address not created!");

    require_auth(name(creator));
    
    uint64_t code = current_receiver().value;


    ethcode_table mytable(name(code), creator);

    auto itr = mytable.find(address_index);

    if (itr == mytable.end()) {
        return false;
    }
    mytable.erase(itr);

    return true;
}

bool eth_account_get_nonce(eth_address& address, uint64_t& nonce) {
    ethaccount account;
    if (!eth_account_get(address, account)) {
        return false;
    }
    nonce = account.nonce;
    return true;
}

bool eth_account_set_nonce(eth_address& address, uint64_t nonce) {
    ethaccount account;
    if (!eth_account_get(address, account)) {
        return 0;
    }
    account.nonce = nonce;
    return eth_account_set(address, account);
}

#ifndef USE_KEY256_VALUE_TABLE
bool eth_account_get_value(eth_address& address, key256& key, value256& value) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    if (!ret) {
        return false;
    }
//    check(ret, "get_value:address not created!");
    
    uint64_t code = current_receiver().value;

    checksum256 _address;
    memset(_address.data(), 0, sizeof(checksum256));
    memcpy(_address.data(), address.data(), SIZE_ADDRESS);

    account_state_table mytable(name(code), address_index);
    auto idx_sec = mytable.get_index<"bykey"_n>();

    checksum256 _key;
    memcpy(_key.data(), key.data(), SIZE_256BIT);

    auto itr = idx_sec.find(_key);
    if (itr == idx_sec.end()) {
        return false;
    }

    memcpy(value.data(), itr->value.data(), SIZE_256BIT);
//    always return true
    return true;
}

bool eth_account_set_value(eth_address& address, key256& key, value256& value) {
    uint64_t creator, address_index;
    uint64_t sender_creator;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_value:address not created!");
//    eosio::check(creator, "set_value: address creator not found!");

#ifdef EVM_FOR_PASS_VMTESTS
    sender_creator = current_receiver().value;
#else
    auto sender = evm_get_origin_address();
    sender_creator = eth_account_find_creator_by_address(sender);
    require_auth(name(sender_creator));
#endif
    uint64_t code = current_receiver().value;

    account_state_table mytable(name(code), address_index);
    auto idx_sec = mytable.get_index<"bykey"_n>();

    checksum256 _key;
    memcpy(_key.data(), key.data(), SIZE_256BIT);

    auto itr = idx_sec.find(_key);
    if (itr == idx_sec.end()) {
        mytable.emplace( name(sender_creator), [&]( auto& row ) {
            uint64_t key256_index = get_next_key256_index(creator);
            row.index = key256_index;
            row.key.resize(32);
            row.value.resize(32);
            memcpy(row.key.data(), key.data(), SIZE_256BIT);
            memcpy(row.value.data(), value.data(), SIZE_256BIT);
        });
    } else {
        auto itr2 = mytable.find(itr->index);
        value256 zero{};
        if (value == zero) {//release storage if value is zero
            mytable.erase(itr2);
        } else {
            mytable.modify( itr2, name(0), [&]( auto& row ) {
                check(row.value.size() == 32, "bad value size!");
                memcpy(row.value.data(), value.data(), SIZE_256BIT);
            });
        }
    }
    return true;
}

bool eth_account_clear_value(eth_address& address, key256& key) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_value:address not created!");


    uint64_t code = current_receiver().value;

    account_state_table mytable(name(code), address_index);
    auto idx_sec = mytable.get_index<"bykey"_n>();

    checksum256 _key;
    memcpy(_key.data(), key.data(), SIZE_256BIT);

    auto itr = idx_sec.find(_key);
    if (itr == idx_sec.end()) {
        return false;
    }
    auto itr2 = mytable.find(itr->index);
    mytable.erase(itr2);
    return true;
}

#else

bool eth_account_set_value(eth_address& address, key256& key, value256& value) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_value:address not created!");

    auto sender = evm_get_origin_address();
    uint64_t sender_creator = eth_account_find_creator_by_address(sender);

    require_auth(name(sender_creator));

    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    uint64_t payer = sender_creator;

    int itr = db_find_i256(code, scope, address_index, key.data(), 32);
    if (itr < 0) {
        db_store_i256(scope, address_index, payer, (char*)key.data(), 32, (char*)value.data(), 32);
    } else {
        db_update_i256(itr, payer, (char*)value.data(), 32);
    }
    return true;
}

bool eth_account_get_value(eth_address& address, key256& key, value256& value) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_value:address not created!");

    uint64_t code = current_receiver().value;
    uint64_t scope = code;
    int itr = db_find_i256(code, scope, address_index, key.data(), 32);
    if (itr < 0) {
        return false;
    }

    int size = db_get_i256(itr, (char*)value.data(), 32);
    check(size == 32, "bad storage!");
    return true;
}

bool eth_account_clear_value(eth_address& address, key256& key) {
    uint64_t creator, address_index;
    bool ret = eth_account_find_creator_and_index_by_address(address, creator, address_index);
    check(ret, "set_value:address not created!");

    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    int itr = db_find_i256(code, scope, address_index, key.data(), 32);
    if (itr < 0) {
        return false;
    } else {
        db_remove_i256(itr);
        return true;
    }
}
#endif

void eth_account_clear_all() {
    uint64_t code = current_receiver().value;
    uint64_t scope = code;

    key256_counter counter(name(code), scope);
    key256counter a = {0};
    counter.set(a, name(0));

    ethaccount_table mytable(name(code), scope);

    while(true) {
        auto itr = mytable.upper_bound(0);
        if (itr == mytable.end()) {
            break;
        }

        account_state_table statetable(name(code), itr->creator);
        while(true) {
            auto itr = statetable.upper_bound(0);
            if (itr == statetable.end()) {
                break;
            }
            statetable.erase(itr);
        }

        ethcode_table codetable(name(code), itr->creator);
        while(true) {
            auto itr = codetable.upper_bound(0);
            if (itr == codetable.end()) {
                break;
            }
            codetable.erase(itr);
        }
        mytable.erase(itr);
    }


    addressmap_table address_map_table(name(code), scope);
    while(true) {
        auto itr = address_map_table.upper_bound(0);
        if (itr == address_map_table.end()) {
            break;
        }
        address_map_table.erase(itr);
    }
}

string n2s(uint64_t value) {
    return name(value).to_string();
}


static eth_address g_sender{};

eth_address& evm_get_origin_address() {
    return g_sender;
}

void evm_set_origin_address(eth_address& addr) {
    g_sender = addr;
}
