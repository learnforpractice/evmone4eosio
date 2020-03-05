#include "evmhost.hpp"

extern "C" void evm_execute_test(const uint8_t* tests, uint32_t _size) {
    size_t size = (size_t)_size;
    auto testexec = rlp::decode<rlp::ByteString,
                                rlp::ByteString,
                                rlp::ByteString,
                                rlp::ByteString,
                                rlp::ByteString,
                                uint256_t,
                                uint256_t,
                                rlp::ByteString,

                                rlp::ByteString,
                                uint256_t,
                                uint256_t,
                                uint256_t,
                                uint256_t,
                                uint256_t
                                >(tests, size);
    auto& address = std::get<0>(testexec);
    auto& caller = std::get<1>(testexec);
    auto& origin = std::get<2>(testexec);
    auto& code = std::get<3>(testexec);
    auto& data = std::get<4>(testexec);
    auto& gas = std::get<5>(testexec);
    auto& gas_price = std::get<6>(testexec);
    auto& value = std::get<7>(testexec);

    auto& coinbase = std::get<8>(testexec);
    auto& difficulty = std::get<9>(testexec);
    auto& gaslimit = std::get<10>(testexec);
    auto& blocknumber = std::get<11>(testexec);
    auto& timestamp = std::get<12>(testexec);
    auto& evm_version = std::get<13>(testexec);

    EOSIO_ASSERT(address.size() == 20, "bad address");
    EOSIO_ASSERT(caller.size() == 20, "bad address");
    EOSIO_ASSERT(origin.size() == 20, "bad address");

    evmc_message msg;
    msg.kind = EVMC_CALL;
    msg.gas = (int64_t)gas;
    memcpy(msg.destination.bytes, address.data(), 20);
    memcpy(msg.sender.bytes, caller.data(), 20);
    msg.input_data = data.data();
    msg.input_size = data.size();
    msg.value = to_uint256(value.data(), (uint32_t)value.size(), 1);

    // "env" : {
    //     "currentCoinbase" : "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
    //     "currentDifficulty" : "0x0100",
    //     "currentGasLimit" : "0x0f4240",
    //     "currentNumber" : "0x00",
    //     "currentTimestamp" : "0x01"
    // },
    evmc_tx_context tx_context{};

    EOSIO_ASSERT(coinbase.size() == 20, "bad coinbase size");
    tx_context.tx_origin = *(evmc_address*)origin.data();
    memcpy(tx_context.block_coinbase.bytes, coinbase.data(), 20);
    tx_context.block_number = (int64_t)blocknumber;
    tx_context.block_timestamp = (int64_t)timestamp;
    tx_context.block_gas_limit = (int64_t)gaslimit;
    intx::be::store(tx_context.tx_gas_price.bytes, gas_price);
    intx::be::store(tx_context.block_difficulty.bytes, difficulty);

    int32_t id = eth_get_chain_id();
    tx_context.chain_id = to_little_endian(id);

    evmc_revision version = EVMC_FRONTIER;
    if (evm_version == 0) {
        version = EVMC_FRONTIER;
    } else if (evm_version == 1) {
        version = EVMC_BYZANTIUM;
    } else if (evm_version == 2) {
        version = EVMC_ISTANBUL;
    }

    auto host = EVMHost(tx_context, version);
    auto evm = evmc::VM{evmc_create_evmone()};

    auto res = evm.execute(host, version, msg, code.data(), code.size());
    if (res.status_code != EVMC_SUCCESS) {
        EOSIO_THROW(get_status_error(res.status_code));
    }

    auto logs = host.get_logs();
    print_result(*(evmc_address*)caller.data(), res.output_data, res.output_size, logs, res.gas_left);
    if (res.status_code != EVMC_SUCCESS) {
        EOSIO_THROW(get_status_error(res.status_code));
    }
}

