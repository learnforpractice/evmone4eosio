import os
import time
import json
import random
import hashlib
import traceback
import platform
import logging

from pyeoskit import wallet
from pyeoskit import eosapi
from pyeoskit import config
from pyeoskit import db
from pyeoskit import util

from pyeoskit.exceptions import HttpAPIError
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(lineno)d %(module)s %(message)s')
# formatter = logging.Formatter('%(asctime)s %(levelname)s %(module)s %(lineno)d %(message)s')
# handler = logging.StreamHandler()
# handler.setFormatter(formatter)

logger=logging.getLogger(__name__)

config.main_token = 'EOS'
db.reset()

if len(sys.argv) == 2:
    print(sys.argv)
    eosapi.set_nodes([sys.argv[1]])

if os.path.exists('mywallet.wallet'):
    os.remove('mywallet.wallet')
psw = wallet.create('mywallet')
print(psw)
priv_keys = [
    '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3',#EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV
    '5JEcwbckBCdmji5j8ZoMHLEUS8TqQiqBG1DRx1X9DN124GUok9s',#EOS61MgZLN7Frbc2J7giU7JdYjy2TqnfWFjZuLXvpHJoKzWAj7Nst
    '5JbDP55GXN7MLcNYKCnJtfKi9aD2HvHAdY7g8m67zFTAFkY1uBB',#EOS5JuNfuZPATy8oPz9KMZV2asKf9m8fb2bSzftvhW55FKQFakzFL
    '5K463ynhZoCDDa4RDcr63cUwWLTnKqmdcoTKTHBjqoKfv4u5V7p',#EOS8Znrtgwt8TfpmbVpTKvA2oB8Nqey625CLN8bCN3TEbgx86Dsvr
    '5KH8vwQkP4QoTwgBtCV5ZYhKmv8mx56WeNrw9AZuhNRXTrPzgYc',#EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV
    '5KT26sGXAywAeUSrQjaRiX9uk9uDGNqC1CSojKByLMp7KRp8Ncw',#EOS8Ep2idd8FkvapNfgUwFCjHBG4EVNAjfUsRRqeghvq9E91tkDaj
]

for priv_key in priv_keys:
    wallet.import_key('mywallet', priv_key)

key1 = 'EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV'
key2 = 'EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV'


def deploy_contract(account_name, contract_name, contracts_path=None):
    if not contracts_path:
        contracts_path = os.path.dirname(__file__)
        contracts_path = os.path.join(contracts_path, 'contracts')

    code_path = os.path.join(contracts_path, f'{contract_name}/{contract_name}.wasm')
    abi_path = os.path.join(contracts_path, f'{contract_name}/{contract_name}.abi')

    logger.info(code_path)
    code = open(code_path, 'rb').read()
    abi = open(abi_path, 'rb').read()

    m = hashlib.sha256()
    m.update(code)
    code_hash = m.hexdigest()

    try:
        r = eosapi.get_code(account_name)
        logger.info((code_hash, r['code_hash']))
        if code_hash != r['code_hash']:
            logger.info(f"++++++++++set contract: {contract_name}")
            r = eosapi.set_contract(account_name, code, abi, 0)
            return True
    except Exception as e:
        print(e)
#        r = eosapi.set_contract(account_name, code, abi, 0)

def create_system_accounts():
    systemAccounts = [
        'eosio.bpay',
        'eosio.msig',
        'eosio.names',
        'eosio.ram',
        'eosio.ramfee',
        'eosio.saving',
        'eosio.stake',
        'eosio.token',
        'eosio.vpay',
        'eosio.rex',
        'hello',
        'helloworld11',
        'helloworld12',
        'helloworld13',
        'helloworld14',
        'helloworld15',
        'helloworld33',
    ]
    newaccount = {'creator': 'eosio',
     'name': '',
     'owner': {'threshold': 1,
               'keys': [{'key': key1,
                         'weight': 1}],
               'accounts': [],
               'waits': []},
     'active': {'threshold': 1,
                'keys': [{'key': key2,
                          'weight': 1}],
                'accounts': [],
                'waits': []}}

    for account in systemAccounts:
        if not eosapi.get_account(account):
            actions = []
            logger.info(('+++++++++create account', account))
            newaccount['name'] = account
            _newaccount = eosapi.pack_args('eosio', 'newaccount', newaccount)
            act = ['eosio', 'newaccount', _newaccount, {'eosio':'active'}]
            actions.append(act)
            rr, cost = eosapi.push_actions(actions)

try:
    eosapi.schedule_protocol_feature_activations(['0ec7e080177b2c02b278d5088611686b49d739925a92d9bfcacd7fc6b74053bd']) #PREACTIVATE_FEATURE
    time.sleep(2.0)
except Exception as e:
    logger.exception(e)

# try:
#     eosapi.update_runtime_options(max_transaction_time=230)
#     time.sleep(2.0)
# except Exception as e:
#     logger.exception(e)

create_system_accounts()

contracts_path = os.path.dirname(__file__)
contracts_path = os.path.join(contracts_path, 'contracts')

if not eosapi.get_raw_code_and_abi('eosio')['wasm']:
    deploy_contract('eosio', 'eosio.bios', contracts_path)

feature_digests = ['ad9e3d8f650687709fd68f4b90b41f7d825a365b02c23a636cef88ac2ac00c43',#RESTRICT_ACTION_TO_SELF
            'ef43112c6543b88db2283a2e077278c315ae2c84719a8b25f25cc88565fbea99', #REPLACE_DEFERRED
            '4a90c00d55454dc5b059055ca213579c6ea856967712a56017487886a4d4cc0f', #NO_DUPLICATE_DEFERRED_ID
            '8ba52fe7a3956c5cd3a656a3174b931d3bb2abb45578befc59f283ecd816a405', #ONLY_BILL_FIRST_AUTHORIZER
            '299dcb6af692324b899b39f16d5a530a33062804e41f09dc97e9f156b4476707', #WTMSIG_BLOCK_SIGNATURES
            'c3a6138c5061cf291310887c0b5c71fcaffeab90d5deb50d3b9e687cead45071', #ACTION_RETURN_VALUE
            '8431d19ea6d9ce0755c32f89237776f8006204447e8299f102d3273cd6b7ce62', #ETHEREUM_VM
]

for digest in feature_digests: 
    try:
        args = {'feature_digest': digest}
        logger.info(f'activate {digest}')
        eosapi.push_action('eosio', 'activate', args, {'eosio':'active'})
    except Exception as e:
        logger.error(e)

deploy_contract('eosio.token', 'eosio.token')

if not eosapi.get_balance('eosio'):
    logger.info('issue system token...')
    msg = {"issuer":"eosio","maximum_supply":f"11000000000.0000 {config.main_token}"}
    r = eosapi.push_action('eosio.token', 'create', msg, {'eosio.token':'active'})
    assert r
    r = eosapi.push_action('eosio.token','issue',{"to":"eosio","quantity":f"1000000000.0000 {config.main_token}","memo":""},{'eosio':'active'})
    assert r

try:
    deploy_contract('eosio.msig', 'eosio.msig')
    deploy_contract('eosio', 'eosio.system')
except Exception as e:
    print(e)

try:
    args = {'version':0, 'core':f'4,{config.main_token}'}
    eosapi.push_action('eosio', 'init', args, {'eosio':'active'})
except Exception as e:
    logger.error(e)

if eosapi.get_balance('helloworld11') <=0:
    r = eosapi.push_action('eosio.token', 'transfer', {"from":"eosio", "to":"helloworld11","quantity":f"10000000.0000 {config.main_token}","memo":""}, {'eosio':'active'})

if eosapi.get_balance('helloworld12') <=0:
    r = eosapi.push_action('eosio.token', 'transfer', {"from":"eosio", "to":"helloworld12","quantity":f"10000000.0000 {config.main_token}","memo":""}, {'eosio':'active'})

if eosapi.get_balance('hello') <=0:
    r = eosapi.push_action('eosio.token', 'transfer', {"from":"eosio", "to":"hello","quantity":f"10000000.0000 {config.main_token}","memo":""}, {'eosio':'active'})

for account in  ('helloworld11', 'helloworld12', 'helloworld13', 'helloworld14', 'helloworld15'):
    eosapi.transfer('eosio', account, 1000.0)
    util.buyrambytes('eosio', account, 5*1024*1024)
    util.dbw('eosio', account, 1.0, 1000)

if deploy_contract('helloworld11', 'ethereum_vm'):
    args = {'chainid': 1}
    try:
        r = eosapi.push_action('helloworld11', 'setchainid', args, {'helloworld11':'active'})
        print(r['processed']['elapsed'])
    except Exception as e:
        print(e)

balance = eosapi.get_balance('hello')
logger.info(f'++++balance: {balance}')
while False:
    n = random.randint(0,10000000)
    elapsed = 0
    for i in range(n, n+10):
        try:
            r = eosapi.transfer('hello', 'eosio', 0.0001, str(i))
            logger.info(r['processed']['elapsed'])
            elapsed += int(r['processed']['elapsed'])
        except Exception as e:
            traceback.print_exc()
            logger.info(f'exception:{e}')

    logger.info(f'AVG: {elapsed/10}')
    logger.info(eosapi.get_balance('hello'))
    time.sleep(2.0)
