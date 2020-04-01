import sys
import json
import time
import rlp
import hashlib
import logging
import unittest
import evm
from evm import Eth, EthAccount
from evm import w3
import base58

from eth_utils import keccak
from solcx import compile_source, compile_files, set_solc_version
from init import *

#set_solc_version('v0.5.8')

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
logger=logging.getLogger(__name__)

def compile_contract(contract_source_code, main_class):
    compiled_sol = compile_source(contract_source_code, evm_version='byzantium') # Compiled source code
    contract_interface = compiled_sol[main_class]
    return contract_interface

def load_contract(file_name, main_class):
    src = open(file_name, 'r').read()
    contract_interface = compile_contract(src, f'<stdin>:{main_class}')
    bytecode = contract_interface['bin']
    print(main_class, bytecode)
    abi = contract_interface['abi']
    return w3.eth.contract(abi=abi, bytecode=bytecode)


class ShareValues(object):
    eth_address = None
    main_eth_address = None
    contract_address = None
    callee_contract_address = None
    tester_contract_address = None

def on_test(func):
    def decorator(self, *args, **kwargs):
        logger.info(f'{bcolors.OKGREEN}++++++++++{type(self).__name__}.{func.__name__}++++++++++++++{bcolors.ENDC}')
        return func(self, *args, **kwargs)
    return decorator

def deploy_evm_contract():
    logger.info(shared.contract_address)
    if shared.contract_address:
        return
    evm.set_current_account(test_account)

    nonce = eth.get_nonce(shared.eth_address)
    e = rlp.encode([bytes.fromhex(shared.eth_address), nonce])
    h = keccak(e)
    expected_address = h[12:].hex()

    #test deploy evm contract
    logger.info(("++++++++++shared.eth_address:", shared.eth_address))
    logs = Greeter.constructor().transact({'from': shared.eth_address})
    shared.contract_address = logs[0].hex()

    logger.info((expected_address, shared.contract_address))

    assert expected_address == shared.contract_address
    assert eth.get_nonce(shared.eth_address) == nonce + 1

    #test get contract code
    code = eth.get_code(shared.contract_address)
    # logger.info(code)
    # logger.info( logs[1].hex())

    assert code
    #  == logs[1].hex()

    logs = Tester.constructor().transact({'from': shared.eth_address})
    shared.tester_contract_address = logs[0].hex()
    logger.info(shared.tester_contract_address)

    logs = Callee.constructor().transact({'from': shared.eth_address})
    shared.callee_contract_address = logs[0].hex()
    logger.info(shared.callee_contract_address)


def init_testcase():
    if shared.eth_address:
        return
    try:
        vm_abi = open('./contracts/ethereum_vm/ethereum_vm.abi', 'rb').read()
        vm_code = open('./contracts/ethereum_vm/ethereum_vm.wasm', 'rb').read()
        r = eosapi.publish_contract('helloworld11', vm_code, vm_abi, vmtype=0, vmversion=0, sign=True, compress=1)
        logger.info(r['processed']['elapsed'])
    except Exception as e:
        print(e)

    try:
        context_file = './gen_context.bin'
        context = open(context_file, 'rb').read()
        r = eosapi.push_action(main_account, 'init', context, {main_account:'active'})
        print(r['processed']['elapsed'])
    except Exception as e:
        print(e)


    a = {
        "account": main_account,
        "permission": "active",
        "parent": "owner",
        "auth": {
            "threshold": 1,
            "keys": [
                {
                    "key": "EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV",
                    "weight": 1
                },
            ],
            "accounts": [{"permission":{"actor":main_account,"permission":"eosio.code"},"weight":1}],
            "waits": []
        }
    }
    r = eosapi.push_action('eosio', 'updateauth', a, {main_account:'owner'})

    args = {'chainid': 1}
    try:
        r = eosapi.push_action(main_account, 'setchainid', args, {main_account:'active'})
        print('++++console:', r['processed']['action_traces'][0]['console'])
        print(r['processed']['elapsed'])
    except Exception as e:
        print(e)

    shared.eth_address = eth.get_binded_address(test_account)
    if not shared.eth_address:
        args = {'account': test_account, 'text': 'hello,world'}
        try:
            r = eosapi.push_action(main_account, 'create', args, {test_account:'active'})
            shared.eth_address = r['processed']['action_traces'][0]['console']
            logger.info(('eth address:', shared.eth_address))
            logger.info(r['processed']['elapsed'])
        except Exception as e:
            if hasattr(e, 'response'):
                parsed = json.loads(e.response)
                print('+++error:\n', json.dumps(parsed, indent=4))
            else:
                print(e)
            sys.exit(-1)
        assert shared.eth_address == eth.get_binded_address(test_account)

        assert eth.get_balance(shared.eth_address) == 0.0
        assert eth.get_nonce(shared.eth_address) == 1

    #verify eth address
    e = rlp.encode([test_account, 'hello,world'])
    h = keccak(e)
    logger.info((h[12:].hex(), shared.eth_address))
    assert h[12:].hex() == shared.eth_address
    shared.contract_address = None

    shared.main_eth_address = eth.get_binded_address(main_account)
    if not shared.main_eth_address:
        args = {'account': main_account, 'text': 'hello,world'}
        try:
            r = eosapi.push_action(main_account, 'create', args, {main_account:'active'})
            shared.main_eth_address = r['processed']['action_traces'][0]['console']
            print('eth address:', shared.main_eth_address)
            print(r['processed']['elapsed'])
        except Exception as e:
            if hasattr(e, 'response'):
                parsed = json.loads(e.response)
                print('+++error:\n', json.dumps(parsed, indent=4))
            else:
                print(e)
            sys.exit(-1)
        assert shared.main_eth_address == eth.get_binded_address(main_account)

        assert eth.get_balance(shared.main_eth_address) == 0.0
        assert eth.get_nonce(shared.main_eth_address) == 1
    eosapi.transfer(test_account, main_account, 10.0, 'deposit')

    deploy_evm_contract()

class BaseTestCase(unittest.TestCase):

    def __init__(self, testName, extra_args=[]):
        super(BaseTestCase, self).__init__(testName)
        self.init_testcase()

    @classmethod
    def init_testcase(cls):
        pass

    @classmethod
    def tearDownClass(cls):
        pass

class EVMTestCaseCreate(unittest.TestCase):
    def __init__(self, testName, extra_args=[]):
        super(EVMTestCaseCreate, self).__init__(testName)
        self.extra_args = extra_args
        
        evm.set_current_account(test_account)
        evm.set_chain_id(1)

    @classmethod
    def setUpClass(cls):
        BaseTestCase.setUpClass()

    @on_test
    def test_deploy_evm_contract(self):
        # Deposit Test
        logger.info(('++++++++++shared.eth_address:', shared.eth_address))
        logs = Empty.constructor().transact({'from': shared.eth_address})
        logger.info(logs[0].hex())

    @on_test
    def test_deploy_evm_contract_with_value(self):
        nonce = eth.get_nonce(shared.eth_address)
        e = rlp.encode([bytes.fromhex(shared.eth_address), nonce])
        h = keccak(e)
        new_address = h[12:].hex()

        # Deposit Test
        logger.info(('++++++++++shared.eth_address:', shared.eth_address))
        logs = PayableConstructor.constructor().transact({'from': shared.eth_address, 'value':10})

        assert logs[0].hex() == new_address
        assert eth.get_balance(new_address) == 10



class EVMTestCase(BaseTestCase):
    def __init__(self, testName, extra_args=[]):
        super(EVMTestCase, self).__init__(testName)
        self.extra_args = extra_args
        
        evm.set_current_account(test_account)
        evm.set_chain_id(1)

    @classmethod
    def setUpClass(cls):
        BaseTestCase.setUpClass()

    def deposit(self, account, amount):
        evm.set_current_account(test_account)
        r = eosapi.transfer(account, main_account, amount, 'deposit')

    @on_test
    def test_deposit(self):
        # Deposit Test
        evm.set_current_account(test_account)
        balance = eth.get_balance(shared.eth_address)
        r = eosapi.transfer(test_account, main_account, 10.1, 'deposit')

        eth_balance = eth.get_balance(shared.eth_address)
        logger.info(('++++balance:', balance, eth_balance))
        assert eth_balance == balance + 10*10000+1000

    @on_test
    def test_withdraw(self):
        ### Withdraw test
        evm.set_current_account(test_account)
        args = {'account': test_account, 'amount': '1.0000 SYS'}
        try:
            eos_balance = eosapi.get_balance(test_account)
            eth_balance = eth.get_balance(shared.eth_address)
            
            r = eosapi.push_action(main_account, 'withdraw', args, {test_account:'active'})
            print('++++console:', r['processed']['action_traces'][0]['console'])
            print(r['processed']['elapsed'])

            assert eth_balance - 1.0 == eth.get_balance(shared.eth_address)
            assert eos_balance + 1.0 == eosapi.get_balance(test_account)
        except Exception as e:
            print(e)

    @on_test
    def test_overdraw(self):
        #Overdraw test
        evm.set_current_account(test_account)

        eth_balance = eth.get_balance(shared.eth_address)
        logger.info(('++++eth_balance:', eth_balance))
        args = {'account': test_account, 'amount': '%.4f SYS'%(eth_balance+0.1,)}
        logger.info(('++++args:', args))
        try:
            r = eosapi.push_action(main_account, 'withdraw', args, {test_account:'active'})
            print('++++console:', r['processed']['action_traces'][0]['console'])
            #should not go here
            assert 0
        except Exception as e:
            assert eth_balance == eth.get_balance(shared.eth_address)
            e = json.loads(e.response)
            assert e['error']['details'][0]['message'] == "assertion failure with message: balance overdraw!"

    @on_test
    def test_set_value(self):
        evm.set_current_account(test_account)

        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        #test storage
        args = {'from': shared.eth_address,'to': checksum_contract_address}

        logs = Greeter.functions.setValue(0xaabbccddee).transact(args)
        logger.info((logs, keccak(b'onSetValue(uint256)')))
        logger.info(logs[2][0])
        assert logs[2][0][1][0] == keccak(b'onSetValue(uint256)')
        evm.format_log(logs)
        logger.info(logs)

    @on_test
    def test_get_value(self):
        evm.set_current_account(test_account)

        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        #test storage
        args = {'from': shared.eth_address,'to': checksum_contract_address}

        logs = Greeter.functions.getValue().transact(args)
        logger.info(logs)

# [b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', 
# b'',
# [b'\xf9\x8a\xea\xf5\xdb\xa7\x92gk\xdc\xec#\xe3a\xfc\x1b0\x1e\x95e', 
# [
#     b'\xf4\x8a\x1d\xc5~\xef\xa3\xdeD\x06\xe6_\xc0\xfc7{%\xd1\x00\xbd\x06B\x92\x01\xa0\x1a\x9e\x8e\x0e\x1d\x07s'
# ], 
# b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xaa\xbb\xcc\xdd\xee'
# ]


        values = eth.get_all_values(shared.contract_address)
        logger.info(values)
        # contract_address = w3.toChecksumAddress(output['new_address'])
        # print('+++contract_address:', contract_address)

    @on_test
    def test_authorization(self):
        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        logger.info(f'{bcolors.OKGREEN}++++++++++test call evm contract with wrong authorization{bcolors.ENDC}')
        try:
            evm.set_current_account(main_account)
            args = {'from': shared.eth_address,'to': checksum_contract_address}
            ret = Greeter.functions.setValue(0xaabbccddee).transact(args)
            assert 0
        except Exception as e:
            e = json.loads(e.response)
            assert e['error']['details'][0]['message'] == 'missing authority of helloworld12'

    def transfer_eth(self, _from, _to, _value):
        evm.set_current_account('helloworld12')
        args = {'from': w3.toChecksumAddress(_from),'to': w3.toChecksumAddress(_to), 'value':_value}
        ret = Greeter.functions.transfer().transact(args)

    @on_test
    def test_transfer_eth(self):
        evm.set_current_account('helloworld12')
        eosapi.transfer('helloworld12', main_account, 1.0)
        balance1 = eth.get_balance(shared.eth_address)
        balance2 = eth.get_balance(shared.main_eth_address)

        ram_usage_main_account = eosapi.get_account(main_account)['ram_usage']
        ram_usage_test_account = eosapi.get_account(test_account)['ram_usage']

        transaction = {
                'from':shared.eth_address,
                'to': w3.toChecksumAddress(shared.main_eth_address),
                'value': 1000,
                'gas': 2000000,
                'gasPrice': 234567897654321,
                'nonce': 0,
                'chainId': 1
        }
        w3.eth.sendTransaction(transaction)

        logger.info((balance1, eth.get_balance(shared.eth_address)))

        assert balance1 == eth.get_balance(shared.eth_address)+1000
        assert balance2+1000 == eth.get_balance(shared.main_eth_address)

        assert ram_usage_main_account == eosapi.get_account(main_account)['ram_usage']
        assert ram_usage_test_account == eosapi.get_account(test_account)['ram_usage']

    @on_test
    def test_transfer_eth_to_not_created_address(self):
        evm.set_current_account('helloworld12')
        eosapi.transfer('helloworld12', 'helloworld11', 1.0, 'hello')
        transaction = {
                'from':shared.eth_address,
                'to': '0xF0109fC8DF283027b6285cc889F5aA624EaC1F55',
                'value': 1000,
                'gas': 2000000,
                'gasPrice': 0,
                'nonce': 0,
                'chainId': 1
        }
        try:
            w3.eth.sendTransaction(transaction)
        except Exception as e:
            logger.info(e)
            e = json.loads(e.response)
            assert e['error']['details'][0]['message'] == "assertion failure with message: eth address does not exists!"

    @on_test
    def test_transfer_back(self):
        evm.set_current_account(test_account)

        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        
        self.deposit(test_account, 1.0)

        logger.info((shared.eth_address, "balance", eth.get_balance(shared.eth_address)))
        self.transfer_eth(shared.eth_address, shared.contract_address, 1000)

        balance1 = eth.get_balance(shared.eth_address)
        balance2 = eth.get_balance(shared.contract_address)

        logger.info((balance1, balance2))

        args = {'from': shared.eth_address,'to': checksum_contract_address}
        logs = Greeter.functions.transferBack(1000).transact(args)

        balance1 = eth.get_balance(shared.eth_address)
        balance2 = eth.get_balance(shared.contract_address)
        logger.info((balance1, balance2))

        evm.format_log(logs)
        logger.info(logs)

    @on_test
    def test_check_balance(self):
        evm.set_current_account(test_account)
        checksum_contract_address = w3.toChecksumAddress(shared.contract_address)
        self.transfer_eth(shared.eth_address, checksum_contract_address, 10000)

        args = {'from': shared.eth_address,'to': checksum_contract_address}
        balance = eth.get_balance(shared.eth_address)
        balance_contract = eth.get_balance(shared.contract_address)

        logger.info((balance, balance_contract))

        logs = Greeter.functions.checkBalance(balance).transact(args)

        evm.format_log(logs)
        print(logs)


    @on_test
    def test_block_info(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}
        logs = Greeter.functions.testBlockInfo().transact(args)

    @on_test
    def test_origin(self):
        evm.set_current_account(test_account)

        origin = _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}
        logs = Greeter.functions.testOrigin(origin).transact(args)

    @on_test
    def test_ecrecover(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}

        from eth_keys import keys
        from eth_utils import keccak, to_bytes
        h = keccak(b'a message')
        pk = keys.PrivateKey(b'\x01' * 32)
        sign = pk.sign_msg_hash(h)
        print(h, sign.v, sign.r, sign.s)
        r = to_bytes(sign.r)
        s = to_bytes(sign.s)
        logs = Greeter.functions.ecrecoverTest(h, sign.v+27, r, s).transact(args)
        logger.info(logs)
        pub_key = sign.recover_public_key_from_msg(b'a message')
        address = pub_key.to_canonical_address()
        logger.info(pub_key)
        logger.info(address)
        assert logs[1][12:] == address

    @on_test
    def test_ripemd160(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}

        logs = Greeter.functions.ripemd160Test(b'a message').transact(args)
        logger.info(logs)

        import hashlib
        h = hashlib.new('ripemd160')
        h.update(b'a message')
        digest = h.digest()
        logger.info((digest))
        assert logs[1][:20] == digest

    @on_test
    def test_sha256(self):
        evm.set_current_account(test_account)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}

        logs = Greeter.functions.sha256Test(b'another message').transact(args)
        logger.info(logs)

        import hashlib
        h = hashlib.sha256()
        h.update(b'another message')
        digest = h.digest()
        logger.info((digest))
        assert logs[1] == digest

    @on_test
    def test_check_chain_id(self):
        # evm.set_chain_id(2)
        args = {'chainid': 2}
        r = eosapi.push_action(main_account, 'setchainid', args, {main_account:'active'})
        print('++++console:', r['processed']['action_traces'][0]['console'])
        print(r['processed']['elapsed'])

        transaction = {
                'from':shared.eth_address,
                'to': w3.toChecksumAddress(shared.main_eth_address),
                'value': 1000,
                'gas': 2000000,
                'gasPrice': 1,
                'nonce': 0,
                'chainId': 1
        }
        try:
            w3.eth.sendTransaction(transaction)
        except Exception as e:
            e = json.loads(e.response)
            logger.info(e['error']['details'][0]['message'])
            assert e['error']['details'][0]['message'] == "assertion failure with message: bad chain id!"

        time.sleep(0.5)
        evm.set_chain_id(1)
        args = {'chainid': 1}
        r = eosapi.push_action(main_account, 'setchainid', args, {main_account:'active'})
        print('++++console:', r['processed']['action_traces'][0]['console'])
        print(r['processed']['elapsed'])
        logger.info(shared.main_eth_address)
        transaction = {
                'from':shared.eth_address,
                'to': w3.toChecksumAddress(shared.main_eth_address),
                'value': 1,
                'gas': 2000000,
                'gasPrice': 2,
                'nonce': 0,
                'chainId': 1
        }
        w3.eth.sendTransaction(transaction)

    @on_test
    def test_sign_with_eos_private_key(self):
        pub_key = 'EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV'
        eth_address = evm.gen_eth_address_from_eos_public_key(pub_key)
        logger.info(eth_address)
        binded_address = eth.get_binded_address('helloworld13')
        if not binded_address:
            evm.set_eos_public_key(pub_key)
            name = 'helloworld13'
            args = {'account': name, 'address': eth_address}
            eosapi.push_action(main_account, 'bind', args, {name:'active'})
            binded_address = eth.get_binded_address('helloworld13')
        assert eth_address == binded_address
        evm.set_eos_public_key(None)

        eosapi.transfer('helloworld13', 'helloworld11', 10.0, 'deposit')

        transaction = {
            'nonce': eth.get_nonce(eth_address),
            'gasPrice': 2,
            'gas': 3,
            'to':  bytes.fromhex(shared.main_eth_address),
            'value': 1000,
            'data': b'123'
        }
        encoded_trx = evm.sign_transaction_dict_with_eos_key(transaction, 1, pub_key)

        balance = eth.get_balance(eth_address)
        main_balance = eth.get_balance(shared.main_eth_address)

        eosapi.push_action(main_account, 'raw', {'trx':encoded_trx.hex(), 'sender':''}, {'helloworld13':'active'})

        balance2 = eth.get_balance(eth_address)
        main_balance2 = eth.get_balance(shared.main_eth_address)


    @on_test
    def test_ecrecover_with_eos_key(self):
        evm.set_current_account(test_account)

        pub_key = 'EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV'
        eth_address = evm.gen_eth_address_from_eos_public_key(pub_key)

        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.contract_address)
        args = {'from': _from, 'to': _to}

        from eth_keys import keys
        from eth_utils import keccak, to_bytes
        h = keccak(b'a message')

        base58_sign = wallet.sign_digest(h, pub_key)
        sign = base58.b58decode(base58_sign[7:])
        print(sign)
        v = sign[0]
        sign = sign[1:-4]
    #    v = chain_id + (sign[0]<<24)+0x800000
        print('+++v:', v)
        
        r = sign[:32]
        s = sign[32:32+32]

        logs = Greeter.functions.ecrecoverTest(h, v, r, s).transact(args)
        recover_pub_key = eosapi.recover_key(h.hex(), base58_sign)
        logger.info(recover_pub_key)

        recover_address = evm.gen_eth_address_from_eos_public_key(recover_pub_key)
        logger.info(recover_address)
        logger.info(logs[1][12:].hex())
        assert logs[1][12:].hex() == recover_address

    def setUp(self):
        pass

    def tearDown(self):
        pass

class EVMTestCase2(BaseTestCase):
    
    def __init__(self, testName, extra_args=[]):
        super().__init__(testName)
        self.extra_args = extra_args
        
        evm.set_current_account(test_account)
        evm.set_chain_id(1)

    @classmethod
    def setUpClass(cls):
        super(EVMTestCase2, cls).setUpClass()

    @on_test
    def test_call_other_contract(self):
        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.tester_contract_address)
        callee_address = w3.toChecksumAddress(shared.callee_contract_address)
        args = {'from': _from, 'to': _to}

        value = 2
        logs = Tester.functions.testCall(callee_address, value).transact(args)
        ret_value = int.from_bytes(logs[1], 'big')
        assert ret_value == value + 1

    @on_test
    def test_suicide(self):
        _from = w3.toChecksumAddress(shared.eth_address)
        _to = w3.toChecksumAddress(shared.tester_contract_address)
        args = {'from': _from, 'to': _to, 'value': 10000}
        logs = Tester.functions.transfer().transact(args)
        logger.info(logs)
        balance11 = eth.get_balance(shared.eth_address)
        balance21 = eth.get_balance(shared.tester_contract_address)
        logger.info((balance11, balance21))
        args = {'from': _from, 'to': _to}
        logs = Tester.functions.testSuicide().transact(args)

        balance12 = eth.get_balance(shared.eth_address)
        balance22 = eth.get_balance(shared.tester_contract_address)
        logger.info((balance12, balance22))

        assert balance22 == 0
        assert balance12 == balance11 + balance21
        assert not eth.get_code(shared.tester_contract_address)


def suite():
    suite = unittest.TestSuite()

    suite.addTest(EVMTestCase('test_deposit'))
    suite.addTest(EVMTestCase('test_withdraw'))
    suite.addTest(EVMTestCase('test_overdraw'))
    suite.addTest(EVMTestCase('test_set_value'))
    suite.addTest(EVMTestCase('test_authorization'))
    suite.addTest(EVMTestCase('test_transfer_eth'))
    suite.addTest(EVMTestCase('test_transfer_eth_to_not_created_address'))
    suite.addTest(EVMTestCase('test_transfer_back'))

    suite.addTest(EVMTestCase2('test_call_other_contract'))

    return suite

main_account = 'helloworld11'
test_account = 'helloworld12'
eth = Eth(main_account)

Greeter = load_contract('sol/greeter.sol', 'Greeter')
Tester = load_contract('sol/tester.sol', 'Tester')
Callee = load_contract('sol/callee.sol', 'Callee')
Empty = load_contract('sol/empty.sol', 'Empty')
PayableConstructor = load_contract('sol/payableconstructor.sol', 'PayableConstructor')

shared = ShareValues()

#evm.set_eos_public_key('EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV')

if __name__ == '__main__':
    # runner = unittest.TextTestRunner(failfast=True)
    # runner.run(suite())
    if len(sys.argv) > 1:
        url = sys.argv[-1]
        url = url.strip()
        if url.startswith('http'):
            eosapi.set_node(url)
            sys.argv.pop()
    init_testcase()
    unittest.main()

print('Done!')

