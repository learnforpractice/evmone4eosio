#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <secp256k1_sha256.h>

#include "utility.hpp"

static secp256k1_context *s_ctx = nullptr;

uint256be to_uint256(int64_t value) {
    uint256be _value{};

    for (int i=0;i<8;i++) {
        _value.bytes[31-i] = ((uint8_t*)&value)[i];
    }
    return _value;
}

uint256be to_uint256(eth_uint256& value) {
    uint256be _value{};

    for (int i=0;i<32;i++) {
        _value.bytes[31-i] = ((uint8_t*)&value)[i];
    }
    return _value;
}

uint256be to_little_endian(int64_t value) {
    uint256be _value{};

    for (int i=0;i<8;i++) {
        _value.bytes[i] = ((uint8_t*)&value)[i];
    }
    return _value;
}

uint256be to_little_endian(const uint8_t* value, uint32_t size) {
    uint256be _value{};

    for (uint32_t i=0;i<size;i++) {
        _value.bytes[i] = value[size-1-i];
    }
    return _value;
}

uint256be to_uint256(const uint8_t* data, uint32_t size, int endian) {
    uint256be big_encoded{};
    EOSIO_ASSERT(size <=32, "size must <=32");
    if (endian == 0) {
        for (uint32_t i=0;i<size;i++) {
            big_encoded.bytes[31-i] = data[i];
        }
    } else {
      const auto offset = 32 - size;
      memcpy(big_encoded.bytes + offset, data, size);
    }
    return big_encoded;
}

uint32_t big_endian_to_uint32(const uint8_t* data, uint32_t size) {
    EOSIO_ASSERT(size <= 4, "bad size");
    uint32_t value = 0;
    for (uint32_t i=0;i<size;i++) {
        ((uint8_t*)&value)[i] = data[size-1-i];
    }
    return value;
}

uint256be to_balance(const uint8_t* data, uint32_t size) {
    uint256be balance{};
    EOSIO_ASSERT(size <=32, "size must <=32");
    for (uint32_t i=0;i<size;i++) {
        balance.bytes[i] = data[size-1-i];
    }
    return to_uint256(balance.bytes, 32);
}

std::string to_hex(const uint8_t* data, uint32_t size)
{
    static const auto hex_chars = "0123456789abcdef";
    std::string str;
    str.reserve(size * 2);
    for (uint32_t i=0;i<size;i++)
    {
        uint8_t b = data[i];
        str.push_back(hex_chars[uint8_t(b) >> 4]);
        str.push_back(hex_chars[uint8_t(b) & 0xf]);
    }
    return str;
}

void print_hex(const uint8_t* data, uint32_t size) {
    auto hex = to_hex(data, size);
    vmelog("%s\n", hex.c_str());
}



rlp::ByteString encode_topics(vector<bytes32>& topics) {
    rlp::ByteString bs, output;

    for (auto& topic: topics) {
        bs = rlp::ByteString(topic.bytes, topic.bytes + 32);
        bs = rlp::encode(bs);
        output.insert(output.end(), bs.begin(), bs.end());
    }

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    return output;
}

rlp::ByteString encode_log(evm_log& log) {
    rlp::ByteString bs, output;

    bs = rlp::ByteString(log.addr.bytes, log.addr.bytes + 20);
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());

    bs = encode_topics(log.topics);
    output.insert(output.end(), bs.begin(), bs.end());

    bs = rlp::ByteString(log.data.data(), log.data.data() + log.data.size());
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    return output;
}

rlp::ByteString encode_logs(vector<evm_log>& logs) {
    rlp::ByteString output;
    for (auto& log: logs) {
        auto bs = encode_log(log);
        output.insert(output.end(), bs.begin(), bs.end());
    }

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    return output;
}

void print_result(evmc_address& address, const uint8_t* output_data, size_t output_size, vector<evm_log>& logs, int64_t gas_cost) {
    vector<rlp::ByteString> vec;
    rlp::ByteString bs, output;

    bs = rlp::ByteString(address.bytes, address.bytes + 20);
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());
    if (output_size > 0) {
        bs = rlp::ByteString(output_data, output_data + output_size);
    } else {
        bs = rlp::ByteString();
    }
    bs = rlp::encode(bs);
    output.insert(output.end(), bs.begin(), bs.end());

    bs = encode_logs(logs);
    output.insert(output.end(), bs.begin(), bs.end());

    bs = rlp::encode((uint64_t)gas_cost);
    output.insert(output.end(), bs.begin(), bs.end());

    // rlp::ByteString prefix;
    // rlp::encode_details::prefix_multiple_length(output.size(), prefix);
    // printhex(prefix.data(), uint32_t(prefix.size()));
    // printhex(output.data(), uint32_t(output.size()));

    rlp::encode_details::prefix_multiple_length(output.size(), output);
    printhex(output.data(), uint32_t(output.size()));
}

void check_chain_id(int32_t id) {
    EOSIO_ASSERT(id == eth_get_chain_id() || id == -4, "bad chain id!");
}

const char *get_status_error(evmc_status_code& status_code) {
    switch (status_code) {
        case EVMC_SUCCESS:
            return "evmc success";
        case EVMC_FAILURE:
            return "evmc failure";
        case EVMC_REVERT:
            return "evmc revert";
        case EVMC_OUT_OF_GAS:
            return "evmc out of gas";
        case EVMC_INVALID_INSTRUCTION:
            return "evmc invalid instruction";
        case EVMC_UNDEFINED_INSTRUCTION:
            return "evmc undefined instruction";
        case EVMC_STACK_OVERFLOW:
            return "evmc stack overflow";
        case EVMC_STACK_UNDERFLOW:
            return "evmc stack underflow";
        case EVMC_BAD_JUMP_DESTINATION:
            return "evmc bad jump destination";
        case EVMC_INVALID_MEMORY_ACCESS:
            return "evmc invalid memory access";
        case EVMC_CALL_DEPTH_EXCEEDED:
            return "evmc call depth exceeded";
        case EVMC_STATIC_MODE_VIOLATION:
            return "evmc static mode violation";
        case EVMC_PRECOMPILE_FAILURE:
            return "evmc precompile_failure";
        case EVMC_CONTRACT_VALIDATION_FAILURE:
            return "evmc contract validation failure";
        case EVMC_ARGUMENT_OUT_OF_RANGE:
            return "evmc argument out of range";
        case EVMC_WASM_UNREACHABLE_INSTRUCTION:
            return "evmc wasm unreachable instruction";
        case EVMC_WASM_TRAP:
            return "evmc wasm trap";
        case EVMC_INTERNAL_ERROR:
            return "evmc internal error";
        case EVMC_REJECTED:
            return "evmc rejected";
        case EVMC_OUT_OF_MEMORY:
            return "evmc out of memory";
        default:
            return "unknow error";
    }
}

extern "C" EVMC_EXPORT int evm_init() {
    s_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return 0;
}

#ifdef __WASM
extern "C" void load_secp256k1_ecmult_static_context();
#endif

extern "C" EVMC_EXPORT int evm_recover_key(const uint8_t* _signature, uint32_t _signature_size, const uint8_t* _message, uint32_t _message_len, uint8_t* _serialized_public_key, uint32_t _serialized_public_key_size) {    
    if (_signature_size != 65 || _message_len != 32 || _serialized_public_key_size != 65) {
        EOSIO_THROW("wrong argument size");
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
