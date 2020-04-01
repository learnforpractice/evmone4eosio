pragma solidity ^0.6.0;
contract Callee {
    uint myvalue;

    constructor() public {
    }
    
    function setValue(uint v) public returns(uint) {
        myvalue = v;
        return v+1;
    }
}
