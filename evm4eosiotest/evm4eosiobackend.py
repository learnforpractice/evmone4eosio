import os
import sys
import json
import rlp
from eth.rlp.logs import Log
from eth.rlp.receipts import Receipt

from eth.rlp.transactions import (
    BaseTransaction,
    BaseUnsignedTransaction,
)
from eth.rlp.blocks import (
    BaseBlock,
)

from eth_tester.backends.pyevm import PyEVMBackend

from eth.rlp.receipts import Receipt
from eth.vm.computation import BaseComputation
from typing import Tuple

from eth_tester.backends.pyevm.main import get_default_genesis_params
from eth_tester.backends.pyevm.main import get_default_account_keys
from eth_tester.backends.pyevm.main import generate_genesis_state_for_keys

import logging
logger=logging.getLogger(__name__)

from pyeoskit import eosapi, wallet, config
from pyeoskit.exceptions import HttpAPIError

import evm

config.main_token = 'EOS'

if os.path.exists('test.wallet'):
    os.remove('test.wallet')
psw = wallet.create('test')

priv_keys = [
    '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3',#EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV
    '5JEcwbckBCdmji5j8ZoMHLEUS8TqQiqBG1DRx1X9DN124GUok9s',#EOS61MgZLN7Frbc2J7giU7JdYjy2TqnfWFjZuLXvpHJoKzWAj7Nst
    '5JbDP55GXN7MLcNYKCnJtfKi9aD2HvHAdY7g8m67zFTAFkY1uBB',#EOS5JuNfuZPATy8oPz9KMZV2asKf9m8fb2bSzftvhW55FKQFakzFL
    '5K463ynhZoCDDa4RDcr63cUwWLTnKqmdcoTKTHBjqoKfv4u5V7p',#EOS8Znrtgwt8TfpmbVpTKvA2oB8Nqey625CLN8bCN3TEbgx86Dsvr
    '5KH8vwQkP4QoTwgBtCV5ZYhKmv8mx56WeNrw9AZuhNRXTrPzgYc',#EOS7ent7keWbVgvptfYaMYeF2cenMBiwYKcwEuc11uCbStsFKsrmV
    '5KT26sGXAywAeUSrQjaRiX9uk9uDGNqC1CSojKByLMp7KRp8Ncw',#EOS8Ep2idd8FkvapNfgUwFCjHBG4EVNAjfUsRRqeghvq9E91tkDaj
]
for priv_key in priv_keys:
    wallet.import_key('test', priv_key)

import traceback
from eth.vm.forks.constantinople.transactions import ConstantinopleTransaction
from eth.vm.forks.byzantium.transactions import ByzantiumTransaction

def setup_tester_chain(genesis_params=None, genesis_state=None, num_accounts=None):
    from eth.chains.base import MiningChain
    from eth.db import get_db_backend
    from eth.vm.forks.constantinople import ConstantinopleVM

    class ConstantinopleNoProofVM(ConstantinopleVM):
        """Constantinople VM rules, without validating any miner proof of work"""

        @classmethod
        def validate_seal(self, header):
            pass

    class MainnetTesterNoProofChain(MiningChain):
        vm_configuration = ((0, ConstantinopleNoProofVM), )

        @classmethod
        def validate_seal(cls, block):
            pass

        def apply_transaction(self,
                            transaction: BaseTransaction
                            ) -> Tuple[BaseBlock, Receipt, BaseComputation]:
            """
            Applies the transaction to the current tip block.

            WARNING: Receipt and Transaction trie generation is computationally
            heavy and incurs significant performance overhead.
            """
            logger.info(type(transaction))
            # traceback.print_stack()
            vm = self.get_vm(self.header)
            base_block = vm.block
            print(transaction.get_sender().hex())
            gas_used = 100

            contract_name = 'helloworld11'
            account_name = 'helloworld12'
            sender = transaction.get_sender().hex()

            value = transaction.value
#            value = int(value, 16)
            value /= 1e14
            value = round(value)

            unsigned_transaction = ByzantiumTransaction(
                        nonce=transaction.nonce,
                        gas_price=transaction.gas_price,
                        gas=transaction.gas,
                        to=transaction.to,
                        value=value,
                        data=transaction.data,
                        v=evm.eth.get_chain_id(),
                        r=0,
                        s=0,
                    )

            trx = rlp.encode(unsigned_transaction)
            args = {'trx': trx.hex(), 'sender': sender}
            creator = evm.eth.get_creator(sender)
            ret = eosapi.push_action(contract_name, 'raw', args, {creator: 'active'})
            logs = ret['processed']['action_traces'][0]['console']
            logger.info(logs)
            logs = rlp.decode(bytes.fromhex(logs))
            # logger.info(logs)
            logs = logs[2]
            # logger.info(logs)
            for log in logs:
                topics = log[1]
                for i in range(len(topics)):
                    topics[i] = int.from_bytes(topics[i], 'big')
            # logs = (
            #     (
            #         b'\xf2\xe2F\xbbv\xdf\x87l\xef\x8b8\xae\x84\x13\x0fOU\xde9[',
            #         (106851105875418379338862134038057021120564803776635988314411576906050979908793,),
            #         b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05Nihao\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
            #     ),
            # )

            logs = [
                Log(address, topics, data)
                for address, topics, data in logs
            ]

    #        receipt, computation = vm.apply_transaction(base_block.header, transaction)
            receipt = Receipt(state_root=b'\x01', gas_used=gas_used, logs=logs,)
            computation = None
            
            header_with_receipt = vm.add_receipt_to_header(base_block.header, receipt)

            # since we are building the block locally, we have to persist all the incremental state
            vm.state.persist()
            new_header = header_with_receipt.copy(state_root=vm.state.state_root)

            transactions = base_block.transactions + (transaction, )
            receipts = base_block.get_receipts(self.chaindb) + (receipt, )

            new_block = vm.set_block_transactions(base_block, new_header, transactions, receipts)

            self.header = new_block.header

            return new_block, receipt, computation

    if genesis_params is None:
        genesis_params = get_default_genesis_params()

    # if genesis_state:
    #     num_accounts = len(genesis_state)

    # account_keys = get_default_account_keys(quantity=num_accounts)
    account_keys = ()

    if genesis_state is None:
        genesis_state = generate_genesis_state_for_keys(account_keys)

    base_db = get_db_backend(db_path="leveldb")

    chain = MainnetTesterNoProofChain.from_genesis(base_db, genesis_params, genesis_state)
    return account_keys, chain

from eth_tester.backends.pyevm.main import _get_vm_for_block_number
import evm

class MyEVMBackend(PyEVMBackend):

    def __init__(self, genesis_parameters=None, genesis_state=None, main_account='helloworld11'):
        super().__init__(genesis_parameters, genesis_state)
        self.eth = evm.eth

    def estimate_gas(self, transaction):
        return 3000000
        ret = super().estimate_gas(transaction)
        return ret

    def get_nonce(self, account, block_number="latest"):
        print('+++++MyEVMBackend.get_nonce', account.hex())
        a = evm.EthAccount('helloworld11', account.hex())
        return a.get_nonce()

    def get_balance(self, account, block_number="latest"):
        logger.info(('++++get_balance', account))
        return int(1e18)
        return self.eth.get_balance(account)

    def get_code(self, account, block_number="latest"):
        code = self.eth.get_code(account)
        code = bytes.fromhex(code)
        return code

    def call(self, transaction, block_number="latest"):
        # TODO: move this to the VM level.
        defaulted_transaction = transaction.copy()
        logger.info((transaction, type(transaction)))

        if 'gas' not in defaulted_transaction:
            defaulted_transaction['gas'] = self._max_available_gas()

        normalized_transaction = self._normalize_transaction(transaction, block_number)
        unsigned_transaction = self.chain.create_unsigned_transaction(**normalized_transaction)

        sender = transaction['from'].hex()
        contract_name = 'helloworld11'
        account_name = 'helloworld12'
        eth = evm.Eth(contract_name)

        unsigned_transaction = ByzantiumTransaction(
                    nonce=unsigned_transaction.nonce,
                    gas_price=unsigned_transaction.gas_price,
                    gas=unsigned_transaction.gas,
                    to=unsigned_transaction.to,
                    value=unsigned_transaction.value,
                    data=unsigned_transaction.data,
                    v=eth.get_chain_id(),
                    r=0,
                    s=0,
                )

        trx = rlp.encode(unsigned_transaction)

        try:
            args = {'trx': trx.hex(), 'sender': sender}
            ret = eosapi.push_action(contract_name, 'call', args, {account_name:'active'})
        except HttpAPIError as e:
            logger.info(e.response)
            response = json.loads(e.response)
            message = response['error']['details'][1]['message']
            index = message.find(': ')
            output = message[index+2:]
            if not output.strip():
                return b''
            ret = bytes.fromhex(output)
            return rlp.decode(ret)[1]
        '''
        {
            "code":500,
            "message":"Internal Service Error",
            "error":{
                "code":3050003,
                "name":"eosio_assert_message_exception",
                "what":"eosio_assert_message assertion failure",
                "details":[
                    {
                        "message":"assertion failure with message: evm.call",
                        "file":"wasm_interface.cpp",
                        "line_number":1118,
                        "method":"eosio_assert"
                    },
                    {
                        "message":"pending console output: f881941a0b54b21f69b6b2fae269d08de2317d091bb50fb8600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000548656c6c6f000000000000000000000000000000000000000000000000000000c0887ffffffffffff35a",
                        "file":"apply_context.cpp",
                        "line_number":160,
                        "method":"exec_one"
                    }
                ]
            }
        }
        '''            

    def reset_to_genesis(self, genesis_params=None, genesis_state=None, num_accounts=None):
        self.account_keys, self.chain = setup_tester_chain(genesis_params, genesis_state,
                                                            0)
                                                        #    num_accounts)

