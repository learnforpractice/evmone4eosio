import os
import json
import web3
from web3 import Web3
from solcx import link_code
import rlp
import base58

from eth_account._utils.transactions import (
    ChainAwareUnsignedTransaction,
    UnsignedTransaction,
    encode_transaction,
    serializable_unsigned_transaction_from_dict,
    strip_signature,
)

import eth_utils

CHAIN_ID_OFFSET = 35
V_OFFSET = 27

from eth_account.account import Account

from eth_utils import (
    to_dict,
)

from cytoolz import dissoc
from pyeoskit import eosapi, wallet, db, config
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(lineno)d %(module)s %(message)s')
logger=logging.getLogger(__name__)


keys = {
#     'b654a7a81e0aeb7721a22f27a04ecf5af0e8a9a3':'2a2a401e99b8b032fcb20c320af2bc066222eba7c0496e012200e58caf1bfb5a',
#     '75852e7970857bd19fe1984d95ced5aa9760d615':'40b37416a2e9dbec8216da99393353191fae7ccacee0c57b3ed83391a17389dc',
#     'f85a43020b1afd50e78dcbbe3b1ac8f4b07a0919':'8a30bcfc8638d210ec90799cb298f990ca1fb80bd1cba24e82c044a7e028f19c',
#     '2c7536e3605d9c16a7a3d7b1898e529396a65c23':'4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318'
}

g_chain_id = 1
g_current_account = None
g_contract_name = None
g_last_trx_ret = None
g_public_key = None

def format_log(aa):
    for i in range(len(aa)):
        if isinstance(aa[i], bytes):
            aa[i] = aa[i].hex()
        elif isinstance(aa[i], list):
            format_log(aa[i])

def hex2int(h):
    if h[:2] == '0x':
        h = h[2:]
    h = bytes.fromhex(h)
    return int.from_bytes(h, 'big')

def hex2bytes(h):
    if h[:2] == '0x':
        h = h[2:]
    return bytes.fromhex(h)


'''
set ETH chain id
'''
def set_chain_id(id):
    global g_chain_id
    g_chain_id = id

'''
set current account used to sign a EOS transaction
'''
def set_current_account(account):
    global g_current_account
    g_current_account = account

def set_contract_name(account):
    global g_contract_name
    g_contract_name = account

'''
set eos public key which used to sign a ETH transaction
'''
def set_eos_public_key(pub_key):
    global g_public_key
    g_public_key = pub_key

'''
generate a ETH address from a EOS public key
'''
def gen_eth_address_from_eos_public_key(pub_key):
    pub_key = base58.b58decode(pub_key[3:])
    eth_address = eth_utils.keccak(pub_key[:-4])[12:]
    return eth_address.hex()

def get_last_trx_result():
    return g_last_trx_ret

def to_eth_v(v_raw, chain_id=None):
    if chain_id is None:
        v = v_raw + V_OFFSET
    else:
        v = v_raw + CHAIN_ID_OFFSET + 2 * chain_id
    return v

'''
sign a ETH transaction with EOS private key
'''
def sign_transaction_dict_with_eos_key(transaction_dict, chain_id, eos_pub_key):
    # generate RLP-serializable transaction, with defaults filled
    unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction_dict)

    transaction_hash = unsigned_transaction.hash()
    print('transaction hash:', transaction_hash)
    sign = wallet.sign_digest(transaction_hash, eos_pub_key)
    sign = base58.b58decode(sign[7:])
    print(sign)
    v = to_eth_v(0, chain_id + (sign[0]<<24)+0x800000)

    sign = sign[1:-4]    
#    v = chain_id + (sign[0]<<24)+0x800000
    print('+++v:', v)
    r = int.from_bytes(sign[:32], 'big')
    s = int.from_bytes(sign[32:32+32], 'big')

    # serialize transaction with rlp
    encoded_transaction = encode_transaction(unsigned_transaction, vrs=(v, r, s))
    print("++++v, r, s:", v, r, s)
    return encoded_transaction

def pack_transaction(trx):
    global g_chain_id
    trx = dissoc(trx, 'from')
    trx = serializable_unsigned_transaction_from_dict(trx)
    trx = encode_transaction(trx, vrs=(g_chain_id, 0, 0))
    trx = trx.hex()
    return trx

def publish_evm_code(transaction, eos_pub_key = None):
    global g_chain_id
    global g_current_account
    global g_last_trx_ret
    global g_public_key


#    transaction['chainId'] = chain_id #Ethereum mainnet
#     print(transaction)

    sender = transaction['from']
    if sender[:2] == '0x':
        sender = sender[2:]
    sender = sender.lower()
    logger.info(sender)
    a = EthAccount('helloworld11', sender)
    logger.info(('+++++++++sender:', sender))
    nonce = a.get_nonce()
    assert nonce >= 0

    transaction['nonce'] = nonce
    transaction['gasPrice'] = 0
    transaction['gas'] = 20000000

    if sender in keys:
        priv_key = key_maps[sender]
        encoded_transaction = Account.sign_transaction(transaction, priv_key)   
        encoded_transaction = encoded_transaction.rawTransaction.hex()[2:]
    elif g_public_key:
        transaction = dissoc(transaction, 'from')
        encoded_transaction = sign_transaction_dict_with_eos_key(transaction, g_chain_id, g_public_key)
#        logger.info(encoded_transaction)
        encoded_transaction = encoded_transaction.hex()
    else:
        transaction = dissoc(transaction, 'from')
        unsigned_transaction = serializable_unsigned_transaction_from_dict(transaction)
        encoded_transaction = encode_transaction(unsigned_transaction, vrs=(g_chain_id, 0, 0))
        encoded_transaction = encoded_transaction.hex()

    if g_current_account:
        account_name = g_current_account
    else:
        account_name = 'helloworld11'
    
    if g_contract_name:
        contract_name = g_contract_name
    else:
        contract_name = 'helloworld11'
    
    args = {'trx': encoded_transaction, 'sender': sender}
    ret = eosapi.push_action(contract_name, 'raw', args, {account_name:'active'})
    g_last_trx_ret = ret
    logs = ret['processed']['action_traces'][0]['console']
    # logger.info(logs)
    logger.info(('++++elapsed:', ret['processed']['elapsed']))
    try:
        logs = bytes.fromhex(logs)
        logs = rlp.decode(logs)
        # logger.info(logs)
    except Exception as e:
        logger.error(logs)
        raise e
    return logs

class LocalProvider(web3.providers.base.JSONBaseProvider):
    endpoint_uri = None
    _request_args = None
    _request_kwargs = None

    def __init__(self, request_kwargs=None):
        self._request_kwargs = request_kwargs or {}
        super(LocalProvider, self).__init__()

    def __str__(self):
        return "RPC connection {0}".format(self.endpoint_uri)

    @to_dict
    def get_request_kwargs(self):
        if 'headers' not in self._request_kwargs:
            yield 'headers', self.get_request_headers()
        for key, value in self._request_kwargs.items():
            yield key, value

    def request_func_(self, method, params):
        if method == 'eth_sendTransaction':
#             print('----request_func', method, params)
            res = publish_evm_code(params[0])
            #eth_sendTransaction(*params)
            return {"id":1, "jsonrpc": "2.0", 'result': res}
        elif method == 'eth_call':
            return {"id":0,"jsonrpc":"2.0","result":123}
        elif method == 'eth_estimateGas':
            return {"id":0,"jsonrpc":"2.0","result":88}
        elif method == 'eth_blockNumber':
            return {"id":0,"jsonrpc":"2.0","result":15}
        elif method == 'eth_getBlock':
            result = {'author': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'extraData': '0xdc809a312e332e302b2b313436372a4444617277692f6170702f496e74', 'gasLimit': 3141592, 'gasUsed': 0, 'hash': '0x259d3ac184c567e4e3aa3fb0aa6c89d39dd172f6dad2c7e26265b40dce2f8893', 'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'miner': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'number': 138, 'parentHash': '0x7ed0cdae409d5b785ea671e24408ab34b25cb450766e501099ad3050afeff71a', 'receiptsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'sha3Uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'stateRoot': '0x1a0789d0d895011034cda1007a4be75faee0b91093c784ebf246c8651dbf699b', 'timestamp': 1521704325, 'totalDifficulty': 131210, 'transactions': [], 'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'uncles': []}
            return {"id":0,"jsonrpc":"2.0","result":result}
        elif method == 'eth_getBlockByNumber':
            result = {'author': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'extraData': '0xdc809a312e332e302b2b313436372a4444617277692f6170702f496e74', 'gasLimit': 3141592, 'gasUsed': 0, 'hash': '0x259d3ac184c567e4e3aa3fb0aa6c89d39dd172f6dad2c7e26265b40dce2f8893', 'logsBloom': '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000', 'miner': '0x4b8823fda79d1898bd820a4765a94535d90babf3', 'number': 138, 'parentHash': '0x7ed0cdae409d5b785ea671e24408ab34b25cb450766e501099ad3050afeff71a', 'receiptsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'sha3Uncles': '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'stateRoot': '0x1a0789d0d895011034cda1007a4be75faee0b91093c784ebf246c8651dbf699b', 'timestamp': 1521704325, 'totalDifficulty': 131210, 'transactions': [], 'transactionsRoot': '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421', 'uncles': []}
            return {"id":0,"jsonrpc":"2.0","result":result}
        elif method == 'eth_blockNumber':
            return {"id":0,"jsonrpc":"2.0","result":'100'}

    def request_func(self, web3, outer_middlewares):
        '''
        @param outer_middlewares is an iterable of middlewares, ordered by first to execute
        @returns a function that calls all the middleware and eventually self.make_request()
        '''
        return self.request_func_
    
    def get_request_headers(self):
        return {
            'Content-Type': 'application/json',
            'User-Agent': construct_user_agent(str(type(self))),
        }

def get_eth_address_info(contract, eth_addr):
    if eth_addr[:2] == '0x':
        eth_addr = eth_addr[2:]
    args = eosapi.pack_args(contract, 'getaddrinfo', {'address':eth_addr})
    ret = eosapi.call_contract(contract, 'getaddrinfo', args.hex())
    args = ret['results']['output']
    ret = eosapi.unpack_args(contract, 'addrinfo', bytes.fromhex(args))
    return json.loads(ret)

def normalize_address(address):
    if address[:2] == '0x':
        address = address[2:]
    return address.lower()

class Eth(object):
    '''
        Examples:
        >>> import evm
        >>> eth = evm.Eth('helloworld11')
        >>> eth.get_all_address_info()
        [{'index': 1, 'creator': 'helloworld12', 'nonce': 2, 'address': '2c7536e3605d9c16a7a3d7b1898e529396a65c23', 'balance': '9.9000 SYS'}]
        >>> eth.get_address_info('2c7536e3605d9c16a7a3d7b1898e529396a65c23')
        {'index': 1, 'creator': 'helloworld12', 'nonce': 2, 'address': '2c7536e3605d9c16a7a3d7b1898e529396a65c23', 'balance': '9.9000 SYS'}
        >>> eth.get_eth_address_count()
        1
        >>> eth.get_binded_address('helloworld12')
        '2c7536e3605d9c16a7a3d7b1898e529396a65c23'
        >>> eth.get_creator('2c7536e3605d9c16a7a3d7b1898e529396a65c23')
        'helloworld12'
        >>> eth.get_index('2c7536e3605d9c16a7a3d7b1898e529396a65c23')
        1
    '''
    def __init__(self, contract_account):
        self.contract_account = contract_account

#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;
# struct [[eosio::table]] accountcounter {
#     uint64_t                        count;
#     int32_t                         chain_id;
#     EOSLIB_SERIALIZE( accountcounter, (count)(chain_id) )
# };
# typedef eosio::singleton< "global"_n, accountcounter >   account_counter;
    def get_eth_address_count(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global', '', '', '', 1)
        return ret['rows'][0]['count']

    def get_chain_id(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global', '', '', '', 1)
        return ret['rows'][0]['chainid']

#key256_acounter
#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;
# struct [[eosio::table]] key256counter {
#     uint64_t                        count;
#     EOSLIB_SERIALIZE( key256counter, (count) )
# };
#typedef eosio::singleton< "global2"_n, key256counter >   key256_counter;
    def get_total_keys(self):
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'global2', '', '', '', 1)
        if ret['rows']:
            return ret['rows'][0]['count']
        return 0

    def get_all_address_info(self, json=True):
        ret = eosapi.get_table_rows(json, self.contract_account, self.contract_account, 'ethaccount', '', '', '', 10000)
        return ret['rows']

#table ethaccount

#     uint64_t code = current_receiver().value;
#     uint64_t scope = code;

# struct [[eosio::table]] ethaccount {
#     uint64_t                        index;
#     uint64_t                        creator;
#     int32_t                         nonce;
#     std::vector<char>               address;
#     asset                           balance;
#     ethaccount() {
#         address.resize(SIZE_ADDRESS);
#     }
#     uint64_t primary_key() const { return index; }
#     checksum256 by_address() const {
#        auto ret = checksum256();//address;
#        memset(ret.data(), 0, sizeof(checksum256));
#        memcpy(ret.data(), address.data(), SIZE_ADDRESS);
#        return ret;
#     }

#     uint64_t by_creator() const {
#         return creator;
#     }

# typedef multi_index<"ethaccount"_n,
#                 ethaccount,
#                 indexed_by< "byaddress"_n, const_mem_fun<ethaccount, checksum256, &ethaccount::by_address> >,
#                 indexed_by< "bycreator"_n, const_mem_fun<ethaccount, uint64_t, &ethaccount::by_creator> > 
#                 > ethaccount_table;
    def get_address_info(self, address):
        address = normalize_address(address)
        rows = self.get_all_address_info()
        for row in rows:
            if row['address'] == address:
                return row
        return None

    #addressmap
    #     uint64_t code = current_receiver().value;
    #     uint64_t scope = code;
    #primary_index creator
    # struct [[eosio::table]] addressmap {
    #     uint64_t                        creator;
    #     std::vector<char>               address;
    #     uint64_t primary_key() const { return creator; }
    # }
    def get_binded_address(self, account):
        print('+++get_binded_address', account)
        ret = eosapi.get_table_rows(True, self.contract_account, self.contract_account, 'addressmap', account, account, account, 1)
        print(ret)
        if not ret['rows']:
            return
        assert ret['rows'][0]['creator'] == account
        return ret['rows'][0]['address']

    def get_creator(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        if row:
            return row['creator']

    def get_index(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        if row:
            return row['index']

    def get_balance(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        # print(row)
        if row:
            balance = row['balance']
            balance = bytes.fromhex(balance)
            return int.from_bytes(balance, 'little')
        return 0

    def get_nonce(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        if row:
            return row['nonce']

#table account_state
# uint64_t code = current_receiver().value;
# scope = creator
# struct [[eosio::table]] account_state {
#     uint64_t                        index;
#     checksum256                     key;
#     checksum256                     value;
#     uint64_t primary_key() const { return index; }
#     checksum256 by_key() const {
#        return key;
#     }
#     EOSLIB_SERIALIZE( account_state, (index)(key)(value) )
# };

# typedef multi_index<"accountstate"_n,
#                 account_state,
#                 indexed_by< "bykey"_n,
#                 const_mem_fun<account_state, checksum256, &account_state::by_key> > > account_state_table;

    def get_all_values(self, address):
        address = normalize_address(address)
        creator = self.get_creator(address)
        index = self.get_index(address)
        # print('+++++index:', creator, index)
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(True, self.contract_account, index, 'accountstate', '', '', '', 100)
        return ret['rows']

    def get_value(self, address, key):
        address = normalize_address(address)
        creator = self.get_creator(address)
        index = self.get_index(address)
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(True, self.contract_account, index, 'accountstate', '', '', '', 100)
        for row in ret['rows']:
            if row['key'] == key:
                return row['key']
        return None

    def get_code(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        if not row:
            return ''
        index = row['index']
        creator = row['creator']
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(True, self.contract_account, creator, 'ethcode', index, index, index, 1)
        if ret['rows']:
            return ret['rows'][0]['code']
        return ''

    def get_code_cache(self, address):
        address = normalize_address(address)
        row = self.get_address_info(address)
        if not row:
            return ''
        index = row['index']
        creator = row['creator']
        index = eosapi.n2s(index)
        ret = eosapi.get_table_rows(False, self.contract_account, creator, 'ethcodecache', index, index, index, 1)
        if ret['rows']:
            return ret['rows'][0]
        return ''

#     uint64_t code = current_receiver().value;
# scope = creator
# struct [[eosio::table]] ethcode {
#     uint64_t                        index;
#     std::vector<char>               address;
#     vector<char>                    code;
#     uint64_t primary_key() const { return index; }

# typedef multi_index<"ethcode"_n,
#                 ethcode,
#                 indexed_by< "byaddress"_n,
#                 const_mem_fun<ethcode, checksum256, &ethcode::by_address> > > ethcode_table;


class EthAccount(object):
    '''
    Example:
    >>> import evm
    >>> a = evm.EthAccount('helloworld11', '2c7536e3605d9c16a7a3d7b1898e529396a65c23')
    >>> a.get_balance()
    9.9
    >>> a.get_nonce()
    2
    >>> a.get_creator()
    'helloworld12'
    >>> a.get_address_info()
    {'index': 1, 'creator': 'helloworld12', 'nonce': 2, 'address': '2c7536e3605d9c16a7a3d7b1898e529396a65c23', 'balance': '9.9000 SYS'}
    '''
    def __init__(self, contract_account, eth_address):
        self.contract_account = normalize_address(contract_account)
        self.address = normalize_address(eth_address)
        self.eth = Eth(contract_account)

    def get_address_info(self):
        return self.eth.get_address_info(self.address)

    def get_creator(self):
        return self.eth.get_creator(self.address)

    def get_index(self):
        return self.eth.get_index(self.address)

    def get_balance(self):
        return self.eth.get_balance(self.address)

    def get_nonce(self):
        return self.eth.get_nonce(self.address)

    def get_all_values(self):
        return self.eth.get_all_values(self.address)

    def get_value(self, key):
        return self.eth.get_value(self.address, key)

    def get_code(self):
        return self.eth.get_code(self.address)


provider = LocalProvider()
w3 = Web3(provider)
# my_provider = Web3.IPCProvider('/Users/newworld/dev/uuos2/build/aleth/aleth/dd/geth.ipc')
# w3 = Web3(my_provider)
#print(__file__, 'initialization finished!')
