import os
import json
import time
import hashlib
import argparse
import traceback
import logging

import web3
import eth_account
from eth import constants
from eth.chains.mainnet import MainnetChain
from eth.db.atomic import AtomicDB
from eth_utils import to_wei, encode_hex
from eth_utils import decode_hex, encode_hex

from eth_tester.backends.pyevm import PyEVMBackend
from eth_tester import EthereumTester
from eth_tester.main import handle_auto_mining

from flask import Flask,redirect,request
from flask_cors import CORS

from web3.providers.eth_tester import EthereumTesterProvider

from pyeoskit import eosapi, wallet
from provider import EthereumTesterProvider
from evm4eosiobackend import MyEVMBackend

import evm
from ethformatter import request_formatters

GENESIS_PARAMS = {
    'parent_hash': constants.GENESIS_PARENT_HASH,
    'uncles_hash': constants.EMPTY_UNCLE_HASH,
    'coinbase': constants.ZERO_ADDRESS,
    'transaction_root': constants.BLANK_ROOT_HASH,
    'receipt_root': constants.BLANK_ROOT_HASH,
    'difficulty': constants.GENESIS_DIFFICULTY,
    'block_number': constants.GENESIS_BLOCK_NUMBER,
    'gas_limit': 0x7ffffffff,
    'extra_data': constants.GENESIS_EXTRA_DATA,
    'nonce': constants.GENESIS_NONCE
}

class MyEthereumTester(EthereumTester):
    def get_nonce(self, account, block_number="latest"):
        return super().get_nonce(account, block_number)

    @handle_auto_mining
    def send_transaction(self, transaction):
        logger.info(transaction)
        return self._add_transaction_to_pending_block(transaction)

app = Flask(__name__)
cors = CORS(app, resources={r"/*": {"origins": "*"}})

def format_key_value(k):
    while True:
        index = k.find('_')
        if index < 0:
            break
        k = k[:index] + k[index+1].upper() + k[index+2:]
    return k

@app.route('/', methods=['GET', 'POST'])
def on_rpc_request():
    global ethereum

    if request.method == "GET":
        pass
    elif request.method == 'OPTIONS' or request.method == "POST":
        body = request.get_json(force=True)
        logger.info(body)
        req_id = body['id']
        method = body['method']
        if method in request_formatters:
            body['params'] = request_formatters[method](body['params'])

        if method == 'net_listening':
            return {"jsonrpc": "2.0", "id": req_id, "result": True}
        elif method == 'eth_getBalance':
            addr = body['params'][0]
            logger.info(addr)
            result = ethereum.get_balance(addr)
            logger.info(result)
            result *= 1e14
            result = round(result)
            result = hex(result)
            response = {"jsonrpc": "2.0", "id": req_id, "result": result}
            logger.info(response)
            return json.dumps(response)
        else:
            if method == 'eth_getTransactionCount':
                body['params'][1] = evm.hex2int(body['params'][1])
            elif method == 'eth_call':
                if not 'from' in body['params'][0]:
                    body['params'][0]['from'] = w3.eth.defaultAccount
                    body['params'][0]['gas'] = 1
                    balance_checker_address = '0xb1f8e55c7f64d203c1400b9d8555d050f94adf39'
                    ens_address = '0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e'

                    if body['params'][0]['to'] == balance_checker_address:
                        if config.balance_checker_address:
                            body['params'][0]['to'] = config.balance_checker_address
                    elif body['params'][0]['to'] == ens_address:
                        if config.ens_address:
                            body['params'][0]['to'] = config.ens_address
            response = provider.make_request(method, body['params'])

            result = response['result']
            # logger.info(result)
            if isinstance(result, dict):
                res = {}
                for k in result:
                    v = result[k]
                    k = format_key_value(k)
                    if isinstance(v, int):
                        v = hex(v)
                    res[k] = v
                result = res
            elif isinstance(result, int):
                result = hex(result)

            logger.info(result)
 
            # response = {"jsonrpc": "2.0", "id": req_id, "result": block_dict}
            response = {"jsonrpc": "2.0", "id": req_id, "result": result}
            return json.dumps(response)

config = None
ethereum = None
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(lineno)d %(module)s %(message)s')
    logger=logging.getLogger(__name__)
    os.environ['CHAIN_DB_BACKEND_CLASS'] = 'eth.db.backends.level.LevelDB'

    parser = argparse.ArgumentParser(description='Eth to Eos bridge')
    parser.add_argument('--debug', type=bool, default=False, help='set to True to enable debug')
    parser.add_argument('--port', type=int, default=8545, help='port number')
    parser.add_argument('--balance-checker-address', type=str, default='', help='balance checker contract address')
    parser.add_argument('--ens-address', type=str, default='', help='ethereum name service contract address')
    parser.add_argument('--contract-name', type=str, default='helloworld11', help='account name evm code deploy at')
    parser.add_argument('--test-account', type=str, default='helloworld12', help='test account')
    parser.add_argument('--http-server-address', type=str, default='helloworld12', help='test account')

    config = parser.parse_args()

    eosapi.set_node('http://127.0.0.1:8899')

    evm.eth = ethereum = evm.Eth(config.contract_name)

    addr = ethereum.get_binded_address(config.test_account)
    if addr and ethereum.get_balance(addr) == 0:
        eosapi.transfer(config.test_account, config.contract_name, 10.0, 'deposit')

    backend = MyEVMBackend(genesis_parameters=GENESIS_PARAMS, main_account=config.contract_name)
    ethereum_tester = MyEthereumTester(backend=backend)
    provider = EthereumTesterProvider(ethereum_tester=ethereum_tester)
    w3 = web3.Web3(provider)

    try:
        vm_abi = open('../build/lib/evmone/contracts/ethereum_vm.abi', 'rb').read()
        vm_code = open('../build/lib/evmone/contracts/ethereum_vm.wasm', 'rb').read()
        r = eosapi.publish_contract(config.contract_name, vm_code, vm_abi, vmtype=0, vmversion=0, sign=True, compress=1)
        logger.info(r['processed']['elapsed'])
    except Exception as e:
        print(e)

    #public key: 0xdd1f024a414E4C92f9029C4301b45C37cE5330E6
    priv_key_helloworld12 = '5869c5106d7693df84c7d0a81e5f8ae583b55ea5abeb2f06ca6dc04be7040e4b'
    priv_key_helloworld12 = bytes.fromhex(priv_key_helloworld12)
    backend.add_account(priv_key_helloworld12)

    #address binded to helloworld12
    eth_address_helloworld12 = eth_account.account.Account.from_key(priv_key_helloworld12)

    # set pre-funded account as sender
    w3.eth.defaultAccount = eth_address_helloworld12.address
    logger.info(w3.eth.accounts)

    try:
        args = {'account':'helloworld12', 'address': eth_address_helloworld12.address[2:]}
        eosapi.push_action(config.contract_name, 'bind', args, {'helloworld12':'active'})
    except Exception as e:
        print(e)

    #public key: 0x818A2Ce28327E1Af085Ab925a01e511848a089B9
    priv_key_helloworld11 = '8e9c3854f1ccb8ed82c5fc6a7953282a6606e690f80edc7eb714e9b00d829267'
    priv_key_helloworld11 = bytes.fromhex(priv_key_helloworld11)
    backend.add_account(priv_key_helloworld11)

    eth_address_helloworld11 = eth_account.account.Account.from_key(priv_key_helloworld11)

    try:
    #    args = {'account':config.contract_name, 'address': w3.eth.accounts[0][2:]}
        args = {'account':config.contract_name, 'address': eth_address_helloworld11.address[2:]}
        eosapi.push_action(config.contract_name, 'bind', args, {config.contract_name:'active'})
    except Exception as e:
        print(e)

    app.run(debug=config.debug, host='127.0.0.1', port=config.port)
