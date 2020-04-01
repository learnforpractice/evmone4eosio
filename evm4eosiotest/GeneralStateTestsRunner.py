import sys
import json
import time
import rlp
import hashlib
import logging
import unittest
import evm
from evm import Eth, EthAccount
from evm import w3, hex2int, hex2bytes
import base58
import urllib3
import argparse

from eth_utils import keccak
from solcx import compile_source, compile_files
from init import *
from eth_account.account import Account

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(lineno)d %(module)s %(message)s')
#logging.basicConfig(level=logging.INFO, format='%(levelname)s %(lineno)d %(module)s %(message)s')
logger=logging.getLogger(__name__)

def on_test(func):
    def decorator(self, *args, **kwargs):
        logger.info(f'{bcolors.OKGREEN}++++++++++{type(self).__name__}.{func.__name__}++++++++++++++{bcolors.ENDC}')
        return func(self, *args, **kwargs)
    return decorator

def convert_post_storage(s):
    _s = {}
    for key in s:
        value = s[key]
        value = hex2int(value)
        key = hex2int(key)
        _s[key] = value
    return _s

def convert_storage(s):
    out = {}
    for _s in s:
        key = hex2int(_s['key'])
        value = hex2int(_s['value'])
        out[key] = value
    return out

g_counter = 0
g_failed_gas_checking_tests = []

class GasCheckingException(Exception):
    pass

def prepare_env(pre):
    global g_counter
    g_counter += 1
    r = eosapi.push_action('helloworld11', 'clearenv', int.to_bytes(g_counter, 4, 'little'), {'helloworld11': 'active'})

    for addr in pre:
        info = pre[addr]
        balance = evm.hex2int(info['balance'])
        balance = int.to_bytes(balance, 32, 'little')
        balance = balance.hex()
        code = info['code'][2:]
        nonce = evm.hex2int(info['nonce'])

        storage = []
        for key in info['storage']:
            value = info['storage'][key]
            value = hex2int(value)
            key = hex2int(key)
            key = int.to_bytes(key, 32, 'big').hex()
            value = int.to_bytes(value, 32, 'big').hex()
            storage.append(key)
            storage.append(value)

        args = dict(address=addr[2:], nonce=nonce, balance=balance, code=code, storage=storage, counter=g_counter)
        # logger.info(args)
        ret = eosapi.push_action('helloworld11', 'setaddrinfo', args, {'helloworld11': 'active'})
        output = ret['processed']['action_traces'][0]['console']


def run_test(test):
    global g_counter
    global g_failed_gas_check
    g_counter += 1
    trx = test['transaction']
    transaction_index = 0
    for data in trx['data']:
        for gas_limit in trx['gasLimit']:
            for value in trx['value']:
                prepare_env(test['pre'])

                value = hex2int(value)
                gas_price = hex2int(trx['gasPrice'])
                nonce = hex2int(trx['nonce'])
                to = trx['to']
                secret_key = trx['secretKey']
                a = Account.from_key('0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8')
                _from = a.address[2:]

                transaction = dict(nonce=nonce,
                                    gasPrice=gas_price,
                                    gas=gas_limit,
#                                    to=to,
                                    value=value,
                                    data=data)
                logger.info((_from, nonce))
                transaction = evm.pack_transaction(transaction)
                args = {'trx': transaction, 'sender': _from}
                ret = eosapi.push_action('helloworld11', 'raw2', args, {'helloworld11':'active'})
                output = ret['processed']['action_traces'][0]['console']
                logger.info(("++++logs:", output))
                output = bytes.fromhex(output)
                output = rlp.decode(output)
                logs = output[2]
                # logger.info(logs)
                logs = rlp.encode(logs)
                h = keccak(logs)

                assert h.hex() == test['post']['Istanbul'][transaction_index]['logs'][2:]

                transaction_index += 1


def run_test_in_file(json_file):
    with open(json_file, 'r') as f:
        tests = f.read()
    tests = json.loads(tests)

    for name in tests:
        # logger.info(name)
        run_test(tests[name])

def init_testcase():
    try:
        abi_file = './contracts/ethereum_vm/evmtest.abi'
        wasm_file = './contracts/ethereum_vm/evmtest.wasm'

        vm_abi = open(abi_file, 'rb').read()
        from pyeoskit import _hello
        abi = _hello._eosapi.pack_abi(vm_abi)
        setabi = eosapi.pack_args('eosio', 'setabi', {'account':'helloworld11', 'abi':abi.hex()})
        eosapi.push_action('eosio', 'setabi', setabi, {'helloworld11':'active'})

        vm_code = open(wasm_file, 'rb').read()
        r = eosapi.publish_contract('helloworld11', vm_code, vm_abi, vmtype=0, vmversion=0, sign=True, compress=1)
        logger.info(r['processed']['elapsed'])
    except Exception as e:
        logger.info(e)

class EVMTestCase(unittest.TestCase):
    def __init__(self, testName, extra_args=[]):
        super(EVMTestCase, self).__init__(testName)
        self.extra_args = extra_args
        
        evm.set_current_account(test_account)
        evm.set_chain_id(1)

    @classmethod
    def setUpClass(cls):
        super().setUpClass()

    @on_test
    def test_vm_tests(self):
        test_file = '/Users/newworld/dev/ethereum/tests/GeneralStateTests/stArgsZeroOneBalance/addNonConst.json'
        # test_file = '/Users/newworld/dev/ethereum/tests/GeneralStateTests/stBugs/evmBytecode.json'
        # test_file = '/Users/newworld/dev/ethereum/tests/GeneralStateTests/stBugs/randomStatetestDEFAULT-Tue_07_58_41-15153-575192.json'
        run_test_in_file(test_file)
        return

        total_tests = 0
        failed_tests = []
        failed_gas_checking_tests = []
        for root, dirs, files in os.walk(vmtests_dir):
            for file in files:
                if not file.endswith('.json'):
                    continue
                total_tests += 1
                full_file_path = os.path.join(root,  file)
                try:
                    run_test_in_file(full_file_path)
                except urllib3.exceptions.NewConnectionError as e:
                    logger.exception(e)
                    sys.exit(-1)
                except urllib3.exceptions.MaxRetryError as e:
                    logger.exception(e)
                    sys.exit(-1)
                except GasCheckingException as e:
                    failed_gas_checking_tests.append(full_file_path)
                except Exception as e:
                    logger.info(('run test', full_file_path))
                    if hasattr(e, 'response'):
                        e = json.loads(e.response)
                        error_message = e['error']['details'][0]['message']
                        logger.info(error_message)
                        # if file == 'mulUnderFlow.json' and error_message == "assertion failure with message: evmc stack underflow":
                        #     pass
                        # else:
                        #     # logger.exception(e)
                    else:
                        logger.exception(e)
                    failed_tests.append(full_file_path)

        r = eosapi.push_action('helloworld11', 'clearenv', b'clearenv', {'helloworld11': 'active'})

        logger.info(('+++failture tests:', failed_tests))
        logger.info(('++++total tests:', total_tests, 'failed tests:', len(failed_tests)))
        logger.info(failed_gas_checking_tests)
        logger.info(("++++failed_gas_checking_tests:", len(failed_gas_checking_tests)))

        # json_file = os.path.join(root, 'expPowerOf256Of256_14.json')
        # run_test(json_file)


    def setUp(self):
        pass

    def tearDown(self):
        pass

main_account = 'helloworld11'
test_account = 'helloworld12'
eth = Eth(main_account)

vmtests_dir = 'VMTests'
config = None
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-d', '--test-dir',               type=str, default='/Users/newworld/dev/ethereum/tests/GeneralStateTests',          help='VMTests directory')
    parser.add_argument('-a', '--http-server-address',    type=str, default='http://127.0.0.1:8888',  help='http server address')
    parser.add_argument('-v', '--evm-version',    type=int, default=0,  help='which evm version to test, 0 for FRONTIER, 1 for BYZANTIUM, default to 0')

    i = len(sys.argv)
    for arg in sys.argv[::-1]:
        if arg == '--':
            break
        i -= 1
    extra_args = []
    if i > 0:
        extra_args = sys.argv[i:]
        sys.argv = sys.argv[:i-1]

    config = parser.parse_args(extra_args)
    eosapi.set_node(config.http_server_address)
    vmtests_dir = config.test_dir
    if not os.path.exists(vmtests_dir):
        raise Exception('vmtests dir '+'does not exist')

    init_testcase()
    unittest.main()

print('Done!')

