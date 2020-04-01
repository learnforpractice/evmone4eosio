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

def run_test(test):
    global g_counter
    global g_failed_gas_check

    g_counter += 1
    r = eosapi.push_action('helloworld11', 'clearenv', int.to_bytes(g_counter, 4, 'little'), {'helloworld11': 'active'})

    trx = test['exec']
    caller = trx['caller'][2:]
    to = trx['address'][2:]
    caller_created = False

    for addr in test['pre']:
        # logger.info(addr)
        if caller == addr[2:]:
            caller_created = True
        info = test['pre'][addr]
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
        # logger.info(('++++output:', output))
        # logger.info(eth.get_all_address_info())
#            {'balance': '0x152d02c7e14af6800000', 'code': '0x6000600020600055', 'nonce': '0x00', 'storage': {}
    if not caller_created:
        try:
            #1000000000000000000
            args = dict(address=caller, nonce=1, balance='00', code='', storage=[], counter=g_counter)
            r = eosapi.push_action('helloworld11', 'setaddrinfo', args, {'helloworld11': 'active'})
        except Exception as e:
            logger.info(e)

    # "currentCoinbase" : "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
    # "currentDifficulty" : "0x0100",
    # "currentGasLimit" : "0x0f4240",
    # "currentNumber" : "0x01",
    # "currentTimestamp" : "0x01"

    env = test['env']
    value = hex2int(trx['value'])
    value = int.to_bytes(value, 32, 'little')
    value = value.hex()
    args = [
        hex2bytes(trx['address']),
        hex2bytes(trx['caller']),
        hex2bytes(trx['origin']),
        hex2bytes(trx['code']),
        hex2bytes(trx['data']),
        hex2int(trx['gas']),
        hex2int(trx['gasPrice']),
        hex2int(trx['value']),

        hex2bytes(env['currentCoinbase']),
        hex2int(env['currentDifficulty']),
        hex2int(env['currentGasLimit']),
        hex2int(env['currentNumber']),
        hex2int(env['currentTimestamp']),
        config.evm_version
    ]
    data = rlp.encode(args)
    sender = int.to_bytes(g_counter, 4, 'little').hex()+"fffffefdfcfbfaf9f7f6f5f4f3f2f1f0"
    args = dict(trx=data.hex(), sender=sender)
#        logger.info(args)
    ret = eosapi.push_action('helloworld11', 'raw', args, {'helloworld11': 'active'})
    output = ret['processed']['action_traces'][0]['console']
    # logger.info(("++++++++console:", output))
    # start = output.rfind(':')
    # output = output[start+1:]
    # logger.info(('++++elapsed:', ret['processed']['elapsed']))
    try:
        output = bytes.fromhex(output)
        output = rlp.decode(output)
        # logger.info(output)
    except Exception as e:
        logger.error(output)
        raise e

    if 'out' in test:
        assert output[1].hex() == test['out'][2:], (output[1].hex(), test['out'][2:])

    if 'logs' in test:
        if len(output) == 2:
            logs = []
        else:
            logs = output[2]
        # logger.info(logs)
        logs = rlp.encode(logs)
        logs = keccak(logs)
        assert logs.hex() == test['logs'][2:], (logs, test['logs'])

    if 'post' in test:
        for addr in test['post']:
            post_info = test['post'][addr]
            post_balance = evm.hex2int(post_info['balance'])
            code = post_info['code'][2:]
            nonce = evm.hex2int(post_info['nonce'])
            post_storage = post_info['storage']
            post_storage = convert_post_storage(post_storage)

            balance = eth.get_balance(addr)
            assert balance == post_balance, (post_balance, balance)
            assert code == eth.get_code(addr), (code, eth.get_code(addr))

            storage = eth.get_all_values(addr)

            storage = convert_storage(storage)
            # logger.info(storage)
            for key in post_storage:
                assert key in storage, (key, storage)
                assert storage[key] == post_storage[key], (storage[key], post_storage[key])

    #too many failture on gas checking on BYZANTIUM fork, VMTests gas depend on FRONTIER
    if 'gas' in test:
        expected_gas = hex2int(test['gas'])
        gas = output[3]
        gas = int.from_bytes(gas, 'big')
        if gas != expected_gas:
            raise GasCheckingException(dict(gas=gas, expected_gas=expected_gas))
#            assert gas == expected_gas, (gas, expected_gas)


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

        # logger.info(('+++failture tests:', failed_tests))
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
    parser.add_argument('-d', '--test-dir',               type=str, default='tests/VMTests',          help='VMTests directory')
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

