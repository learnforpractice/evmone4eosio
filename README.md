# EVM for EOSIO


# Features

1. C++ API interface for porting any EVM implementaion to EOSIO platform nice and easy.
2. Base on evmone, a fast EVM implementation
3. Native compilation supported(2.5x faster than wasm code running in eos-vm-jit mode)
4. 37% RAM saving via intrinsic db api (288 bytes per kv storage vs 456 bytes per kv storage)
5. Ethereum RPC Interface API supported, allow Dapp on Ethereum platform migrate to EOSIO platform with little changes.


# Setup Pre Requirements:

## Install Prebuilt EOSIO Binaries

Please refer https://github.com/eosio/eos for an installation instruction.


## Install eosio.cdt 1.7.0

### Ubuntu:

```
wget https://github.com/eosio/eosio.cdt/releases/download/v1.7.0/eosio.cdt_1.7.0-1-ubuntu-18.04_amd64.deb
sudo apt install ./eosio.cdt_1.7.0-1-ubuntu-18.04_amd64.deb
```

### Mac OS X:

```
brew tap eosio/eosio.cdt
brew install eosio.cdt
```


# Build

## Build from git repository
```
git clone --branch evm4eosio https://github.com/learnforpractice/evmone4eosio --recursive
cd evmone4eosio
mkdir build
cd build
cmake ..
make -j$(nproc)
```

## Build from a release

Download source code https://github.com/learnforpractice/evmone4eosio/releases
extract the source code to a directory such as evmone4eosio

```
cd evmone4eosio
mkdir build
cd build
cmake ..
make -j$(nproc)
```

That will generate a wasm file locate at lib/evmone/contracts/ethereum_vm.wasm


# Demos & Test

Please refer to [evm4eosiotest](./evm4eosiotest/README.md)


# Implementaion detail

Please refer to [implementaion-detail](./evm4eosiotest/implementaion-detail.md)


## License

[![license badge]][Apache License, Version 2.0]

Licensed under the [Apache License, Version 2.0].
