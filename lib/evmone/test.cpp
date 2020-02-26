

#include <evmc/evmc.hpp>
#include <evmc/loader.h>
#include <evmone/evmone.h>
#include "execution.hpp"
#include "../test/utils/utils.hpp"

#include "eevm/rlp.h"

#include <eth_account.hpp>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_recovery.h>
#include <secp256k1_sha256.h>

#include <ethash/keccak.hpp>

#include <eosiolib_legacy/eosiolib.h>

namespace test {
//#define EVMC_VERSION EVMC_BYZANTIUM
#define EVMC_VERSION EVMC_ISTANBUL

constexpr auto max_gas_limit = std::numeric_limits<int64_t>::max();
evmc_address EmptyAddress{};

extern "C" EVMC_EXPORT int evm_recover_key(const uint8_t* _signature, uint32_t _signature_size, const uint8_t* _message, uint32_t _message_len, uint8_t* _serialized_public_key, uint32_t _serialized_public_key_size);

using namespace eevm;
using namespace std::string_literals;
using namespace std;
using namespace evmc;

uint256be to_uint256(int64_t value) {
    uint256be _value{};

    for (int i=0;i<8;i++) {
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

uint32_t big_endian_to_uint32(const uint8_t* data, int size) {
    EOSIO_ASSERT(size <= 4, "bad size");
    uint32_t value;
    for (int i=0;i<size;i++) {
        ((uint8_t*)&value)[i] = data[size-1-i];
    }
    return value;
}

uint256be to_uint256(const uint8_t* data, int size) {
    uint256be big_encoded{};
    EOSIO_ASSERT(size <=32, "size must <=32");
    for (int i=0;i<size;i++) {
        big_encoded.bytes[31-i] = data[i];
    }
    return big_encoded;
}

int64_t uint256_to_int64(const evmc_uint256be& value) {
    auto _value = to_uint256(value.bytes, 32);
    return *(int64_t*)_value.bytes;
}

uint256be to_balance(const uint8_t* data, int size) {
    uint256be balance{};
    EOSIO_ASSERT(size <=32, "size must <=32");
    for (int i=0;i<size;i++) {
        balance.bytes[i] = data[size-1-i];
    }
    return to_uint256(balance.bytes, 32);
}

struct EVMLog {
    address addr;
    vector<uint8_t> data;
    vector<bytes32> topics;
};

inline std::string to_hex(const uint8_t* data, int size)
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

void print_hex(const uint8_t* data, int size) {
    auto hex = to_hex(data, size);
    vmelog(" %s\n", hex.c_str());
} 


}

using namespace test;

extern "C" __attribute__((visibility("default"))) int test_signature_check() {
    const uint8_t _raw_trx[] = {0xf8,0x66,0x01,0x02,0x03,0x94,0xf0,0x10,0x9f,0xc8,0xdf,0x28,0x30,0x27,0xb6,0x28,0x5c,0xc8,0x89,0xf5,0xaa,0x62,0x4e,0xac,0x1f,0x55,0x82,0x03,0xe8,0x83,0x31,0x32,0x33,0x84,0x3f,0x00,0x00,0x25,0xa0,0x7b,0x69,0xac,0xa7,0x39,0xb7,0xc5,0xf4,0xa5,0xfb,0xac,0x5b,0x5d,0xb2,0x06,0x5a,0x8f,0xc2,0xa8,0x75,0xcf,0xee,0xff,0xcb,0x03,0xc1,0xc2,0x29,0x42,0xd6,0x18,0xa1,0xa0,0x36,0x48,0x4d,0xd8,0x76,0xc5,0x88,0xc7,0x45,0x93,0xb9,0x15,0x18,0x9e,0xe9,0x5a,0x0d,0x32,0x05,0x95,0xdc,0xf4,0xb3,0x55,0xc0,0x2a,0x73,0x6c,0x10,0x4f,0x02,0x01};
    const uint8_t *raw_trx = _raw_trx;
    size_t raw_trx_size = sizeof(raw_trx);

    auto decoded_trx = rlp::decode<uint256_t, uint256_t, uint256_t, rlp::ByteString, rlp::ByteString, rlp::ByteString, rlp::ByteString, rlp::ByteString, rlp::ByteString>(raw_trx, raw_trx_size);
    // std::cout << (uint64_t)std::get<0>(decoded_trx) << std::endl; //nonce
    // std::cout << (uint64_t)std::get<1>(decoded_trx) << std::endl; //gas_price
    // std::cout << (uint64_t)std::get<2>(decoded_trx) << std::endl; //gas_limit

    evmc_address new_address;
    int32_t chain_id = 0;

//        std::cout << (uint64_t)std::get<3>(decoded_trx) << std::endl; //to
    
    auto value = std::get<4>(decoded_trx); //value
    //value is big endian encoded

    // std::cout << (uint64_t)std::get<5>(decoded_trx) << std::endl; // data
    rlp::ByteString _v = std::get<6>(decoded_trx); //v
    uint32_t v = 0;
    v = big_endian_to_uint32(_v.data(), _v.size());
    vmelog("++++++++v: %d\n", v);
    auto r = std::get<7>(decoded_trx); //r
    auto s = std::get<8>(decoded_trx); //s

    EOSIO_ASSERT(r.size() == 32, "bad signature size");
    EOSIO_ASSERT(s.size() == 32, "bad signature size");
    intx::uint256 _r = intx::be::unsafe::load<intx::uint256>(r.data());
    intx::uint256 _s = intx::be::unsafe::load<intx::uint256>(s.data());

    if (v > 36) {
        chain_id = (v - 35) / 2; //v = chain_id *2 + 35
    } else if (v == 27 || v == 28) {
        chain_id = -4;
    }
    else {
        EOSIO_THROW("invalid signature!");
    }
    vmelog("++++++++++chain_id %d \n", chain_id);
    if ((0xff800000 & uint32_t(chain_id)) != 0) {//sign with eos private key
        uint8_t first_byte = uint32_t(chain_id) >> 24; //first byte of eos signature
        chain_id = uint32_t(chain_id) & 0x7fffff;
        vmelog("++++chain_id: %d, first byte: %d\n", chain_id, first_byte);
        uint8_t sign[66];
        sign[0] = 0x00; //K1
        sign[1] = first_byte;
        print_hex(r.data(), 32);
        print_hex(s.data(), 32);
        memcpy(sign+2, r.data(), 32);
        memcpy(sign+2+32, s.data(), 32);
        print_hex(sign, 66);
        uint8_t pub_key[34];
        uint8_t trx_hash[32];

        rlp::ByteString unsigned_trx = rlp::encode(std::get<0>(decoded_trx), std::get<1>(decoded_trx),std::get<2>(decoded_trx),std::get<3>(decoded_trx),std::get<4>(decoded_trx),std::get<5>(decoded_trx));
        auto hash256  = ethash::keccak256(unsigned_trx.data(), unsigned_trx.size());
        print_hex(hash256.bytes, 32);

        uint32_t pub_key_size = ::recover_key((checksum256*)hash256.bytes, (const char *)sign, 66, (char *)pub_key, 34);
        vmelog("+++++pub_key_size %d\n", pub_key_size)
        print_hex(pub_key, 34);

//            uint32_t pub_key_size = ::recover_key(pub_key, 34);
    }
    return 1;
}



int main(int argc, char **argv) {
    test_signature_check();
}
