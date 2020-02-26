# EVM for EOSIO

# Setup Pre Requirements:

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

```
git clone --branch evm4eosio https://github.com/learnforpractice/evmone4eosio --recursive
cd evmone4eosio
mkdir build
cd build
cmake ..
make -j$(nproc)
```

That will generate a wasm file locate at lib/evmone/contracts/evmone.wasm

Refer to [evm4eosio-demo](https://github.com/learnforpractice/evm4eosio-demo) for demos and test code

## License

[![license badge]][Apache License, Version 2.0]

Licensed under the [Apache License, Version 2.0].
