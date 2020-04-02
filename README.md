# EVM for EOSIO

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

Download source code https://github.com/learnforpractice/evmone4eosio-private/releases
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
