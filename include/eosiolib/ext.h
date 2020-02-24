#ifndef EOSIOLIB_EXT_H_
#define EOSIOLIB_EXT_H_

#include <eosiolib/types.h>
#ifdef __cplusplus
extern "C" {
#endif

__attribute__((eosio_wasm_import))
int get_code_size(uint64_t account);

__attribute__((eosio_wasm_import))
int get_code(uint64_t account, char *code, size_t size);


#ifdef __cplusplus
}
#endif

#endif //__EXT_H_
///@} databasec

