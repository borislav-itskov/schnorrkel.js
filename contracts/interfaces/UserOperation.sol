// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.0;

struct UserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    uint256 callGasLimit;
    uint256 verificationGasLimit;
    uint256 preVerifivationGas;
    uint256 maxFeePerGas;
    uint256 maxPriorityFeePerGas;
    bytes paymasterAndData;
    bytes signature;
}

library UserOperationLib{
    function getSender(UserOperation calldata userOp) internal pure returns(address){
        address data;
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    function pack(
        UserOperation calldata userOp
    ) internal pure returns (bytes memory ret) {
        bytes calldata sig = userOp.signature;
        assembly {
            let ofs := userOp
            let len := sub(sub(sig.offset, ofs), 32)
            ret := mload(0x40)
            mstore(0x40, add(ret, add(len, 32)))
            mstore(ret, len)
            calldatacopy(add(ret, 32), ofs, len)
        }
    }

    function hash(
        UserOperation calldata userOp
    ) internal pure returns (bytes32) {
        return keccak256(pack(userOp));
    }
}