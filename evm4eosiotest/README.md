# Get Started

## Install Solidity 0.6.0

### Ubuntu 18.04:

```
sudo apt install software-properties-common
sudo add-apt-repository ppa:ethereum/ethereum
sudo apt-get update
sudo apt-get install solc
```

### Mac OS X:

```
brew update
brew upgrade
brew tap ethereum/ethereum
brew install solidity
```

## Clone Demo From Github
```
git clone https://github.com/learnforpractice/evm4eosio-demo
cd evm4eosio-demo
```

## Setup Python Environment

```
python3.7 -m pip install virtualenv
python3.7 -m virtualenv .venv
. .venv/bin/activate
```

### Install PyEosKit

#### Ubuntu

```
python3.7 -m pip https://github.com/learnforpractice/pyeoskit/releases/download/v0.7.0/pyeoskit-0.7.0-cp37-cp37m-linux_x86_64.whl
```

#### Mac OS X
```
python3.7 -m pip https://github.com/learnforpractice/pyeoskit/releases/download/v0.7.0/pyeoskit-0.7.0-cp37-cp37m-macosx_10_9_x86_64.whl
```

### Install Jupyter Notebook
```
python3.7 -m pip install notebook
```

### Install Solc Compiler
```
python3.7 -m pip install py-solc-x
```

### Install Web3

```
python3.7 -m pip install --pre web3[tester]==5.5.0
```

### Install Base58
```
python3.7 -m pip install base58
```

## Start a Testnet
```
nodeos  --verbose-http-errors  --http-max-response-time-ms 100 --data-dir dd --config-dir cd --wasm-runtime eos-vm-jit --contracts-console -p eosio -e --plugin eosio::producer_plugin --plugin eosio::chain_api_plugin --plugin eosio::producer_api_plugin
```

## Initialize the Testnet
In the same directory, run the following command:
```
python3.7 testnet-init.py http://127.0.0.1:8888
```

modify http://127.0.0.1:8888 to the right url if nodeos's http server is not listening at the default ip and port


That will deploy a Smart Contract at [ethereum_vm](contracts/ethereum_vm) that can run Ethereum Smart Contract to the testnet.

For how to build the Smart Contract, please refer to the following link:

[evmone4eosio](https://github.com/learnforpractice/evmone4eosio)


For test on the new builded ethereum_vm.wasm, copy evm4eos_contract/ethereum_vm.wasm and evm4eos_contract/ethereum_vm.abi from build directory to contracts/ethereum_vm

## Open Jupyter Notebook
In eos-with-evm-demo directory, run the following command
```
python3.7 -m notebook
```

Open hello_evm.ipynb and run code in cell one by one

## Run TestCase

```
python3.7 evm_test.py http://127.0.0.1:8888
```

modify http://127.0.0.1:8888 to the right url if nodeos's http server is not listening at the default ip and port

## Run VMTests

First clone [ethereum tests](https://github.com/ethereum/tests) to your local directory:

```
git clone https://github.com/ethereum/tests
```

Run vm tests with the following command

```
python3.7 testsrunner.py -- --http-server-address http://127.0.0.1:8888 -d tests/VMTests -v 0
```

change tests/VMTests to the properly vm tests directory.

