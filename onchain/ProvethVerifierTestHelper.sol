pragma solidity ^0.5.0;

import "./ProvethVerifier.sol";

// This contract is for testing. It exposes internal methods of
// ProvethVerifier so that we can test them.
//
// *************************************************************
// *** Never deploy this contract!                           ***
// *************************************************************
contract ProvethVerifierTestHelper is ProvethVerifier {

    function exposedDecodeUnsignedTx(bytes calldata rlpUnsignedTx) external pure returns (
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        address to,
        uint256 value,
        bytes memory data,
        bool isContractCreation
    ) {
        UnsignedTransaction memory tx = decodeUnsignedTx(rlpUnsignedTx);
        return (
            tx.nonce,
            tx.gasprice,
            tx.startgas,
            tx.to,
            tx.value,
            tx.data,
            tx.isContractCreation
        );
    }

    function exposedDecodeSignedTx(bytes calldata rlpSignedTx) external pure returns (
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        address to,
        uint256 value,
        bytes memory data,
        uint256 v,
        uint256 r,
        uint256 s,
        bool isContractCreation
    ) {
        SignedTransaction memory tx = decodeSignedTx(rlpSignedTx);
        return (
            tx.nonce,
            tx.gasprice,
            tx.startgas,
            tx.to,
            tx.value,
            tx.data,
            tx.v,
            tx.r,
            tx.s,
            tx.isContractCreation
        );
    }


    function exposedMerklePatriciaCompactDecode(
        bytes calldata compact
    ) external pure returns (
        bool isLeaf,
        bytes memory nibbles
    ) {
        return merklePatriciaCompactDecode(compact);
    }

    function exposedValidateMPTProof(
        bytes32 rootHash,
        bytes calldata mptPath,
        bytes calldata rlpStack
    ) external pure returns (
        bytes memory value
    ) {
        return validateMPTProof(
            rootHash,
            mptPath,
            RLPReader.toList(RLPReader.toRlpItem(rlpStack)));
    }

    function exposedSharedPrefixLength(
        uint xsOffset,
        bytes calldata xs,
        bytes calldata ys
    ) external pure returns (uint) {
        return sharedPrefixLength(xsOffset, xs, ys);
    }
}
