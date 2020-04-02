# 1. The Application MUST persist an “Account Table” consisting of:
> * A unique 160bit account ID
> * A nonce (sequence number)
> * An EOSIO token balance (aka SYS)
> * [optionally,] a unique associated EOSIO account

relative code:
https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/table_struct.hpp#L62


# 2. The Application MUST persist an “Account State Table” per account, if it would not be empty, consisting of:
> * A unique 256bit key
> * A 256bit value

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/table_struct.hpp#L91

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/eth_account.cpp#L480

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/eth_account.cpp#L450

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/eth_account.cpp#L521



# 3.The Application MUST persist an “Account Code Table” per account, if it would not be empty, consisting of:
EVM bytecode associated with account


https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/table_struct.hpp#L113

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/eth_account.cpp#L357

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/eth_account.cpp#L335

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/eth_account.cpp#L387



# 4. The Application MUST execute EVM transactions as faithfully to the Ethereum Yellow Paper as Possible, with the following specific requirements:

1. There will be no effective BLOCK gas limit. Instructions that return a BLOCK limit should return a  sufficiently large supply

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmhost.cpp#L17

2. The TRANSACTION gas limit will be enforced
https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmone4eosio.cpp#L70

3. The sender WILL NOT be billed for the gas, the gas price MAY therefore be locked at some suitable value.

gas price is set to 0

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmhost.cpp#L12

4. All other gas mechanics/instructions should be maintained

5. Block number and timestamp should represent the native EOSIO block number and time

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmhost.cpp#L15


6. Block hash, coinbase, and difficulty should return static values


https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmhost.cpp#L162

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmhost.cpp#L13

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmhost.cpp#L12




# 5. The Application MUST implement an action named “raw”:

Whose inputs are:
> * a binary Ethereum transaction encoded as it appears in a serialized Ethereum block
[optionally,]
> * a 160bit account identifier “Sender”

Which results in the:
> * Appropriate Updates to Account, Account State, and Account Code Tables reflecting the application of the transaction
> * Log output (via EOSIO print intrinsics)

If the “R” and “S” values of the transaction are NOT 0:
> * A transaction containing this action must fail if the signature (V, R, S) within the input does not recover to a valid and known 160bit account identifier in the Accounts Table


If the “R” and “S” values of the transaction are 0:
> * A transaction containing this action must fail if “Sender” input parameter is not present or does not refer to a valid and known 160bit account identifier in the Accounts Table

> * If the associated entry in the Accounts Table has no Associated EOSIO Account OR if the transaction has not been authorized by the Associated EOSIO Account


code:

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmone4eosio.cpp#L61


test case:
```
python3.7 evm_test.py EVMTestCase.test_sign_with_eos_private_key

python3.7 evm_test.py EVMTestCase.test_correct_sender

python3.7 evm_test.py EVMTestCase.test_incorrect_sender

python3.7 evm_test.py EVMTestCase.test_incorrect_sender_authorization
```


# 6. The Application MUST implement an action named “create”:

Whose inputs are:
> * An EOSIO account
> * An arbitrary length string

Which results in new Account Table entry with:
> * Balance = 0
> * Nonce = 1
> * Account identifier = the rightmost 160 bits of the Keccak hash of the RLP encoding of the structure containing only the EOSIO account name and the arbitrary input string.

A transaction containing this action must fail if it is not authorized by the EOSIO account listed in the inputs

A transaction containing this action must fail if an Account Table Entry exists with this EOSIO account associated.


code:

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/ethereum_vm.cpp#L141


# 7. The Application MUST respond to EOSIO token transfers:
7.1 Provided that the EOSIO account in the “from” field of the transfer maps to a known and valid Account Table entry through the entry’s unique Associated EOSIO account

7.2 Transferred tokens should be added to the Account Table entry’s balance


code:

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/ethereum_vm.cpp#L224


# 8. The Application MUST implement an action named “withdraw”:
Whose inputs are:
> * An EOSIO account
> * A token amount

Which results in:
> * Deducting the amount from the associated Account Table Entry’s balance
> * Sending an inline EOSIO token transfer for the amount to the EOSIO account

A transaction containing this action must fail if it is not authorized by the EOSIO account listed in the inputs OR if such a withdrawal would leave the Account Table Entry’s balance negative.


https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/ethereum_vm/ethereum_vm.cpp#L177


# 9. The Application MAY implement additional actions for maintenance or transaction processing so long as they do not violate the key principles of the execution model above.


# 10. The Application MUST implement some method of specifying the “CHAIN_ID” for EIP-155 compatibility:
This MAY be done at compile time
This MAY be done with an additional initialization action


https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmone4eosio.cpp#L106

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmone4eosio.cpp#L122

https://github.com/learnforpractice/evmone4eosio/blob/evm4eosio/lib/evmone/evmone4eosio.cpp#L144

