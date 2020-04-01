pragma solidity ^0.6.0;
contract Greeter {
    uint value;
    uint value2;
    uint value3;
    event onSetValue(uint value);
    event onGetValue(uint value);
    event onTransferBack(uint remainBalance);
    event onEmitBytes(bytes bs);
    
    constructor() public {
        value = 1;
        value2 = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
        value3 = 0x123456789abcdeffffffffffffffffffffffffffffffffffffffffffffffffff;
    }

    // fallback() external payable { }

    // receive() external payable {}

//    function fallback() external payable {}

    function getValue2() payable public returns (uint){
//        msg.sender.transfer(1000);
        emit onGetValue(value);
        return value;
    }

    function getValue() payable public returns (uint){
        return value;
    }

    function setValue(uint v) payable public {
        emit onSetValue(v);
        value = v;
    }
    
    function testBlockInfo() public {
        require(block.gaslimit == 0x7fffffffffffffff);
        require(block.coinbase == address(0));
        require(block.difficulty == 0);
        require(blockhash(0) == 0);
    }

    function transfer() payable public {

    }
    
    function checkBalance(uint balance) payable public {
        require(msg.sender.balance == balance, "bad balance");
    }

    function transferBack(uint balance) payable public {
        uint256 oldBalance = msg.sender.balance;
        msg.sender.transfer(balance);
        uint256 newBalance = msg.sender.balance;
        require(oldBalance + balance == newBalance, "bad balance result");
    }

    function ecrecoverTest(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public returns(address){
        return ecrecover(hash, v, r, s);
    }

    function ripemd160Test(bytes memory s) public returns(bytes20){
        return ripemd160(s);
    }

    function sha256Test(bytes memory s) public returns(bytes32){
        return sha256(s);
    }
    
    function testOrigin(address _origin) public {
        require(tx.origin == _origin);
    }
}
