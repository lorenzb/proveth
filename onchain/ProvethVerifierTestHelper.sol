pragma solidity ^0.4.11;

import "./ProvethVerifier.sol";

// This contract is for testing. It exposes internal methods of
// ProvethVerifier so that we can test them.
//
// *************************************************************
// *** Never deploy this contract!                           ***
// *************************************************************
contract ProvethVerifierTestHelper is ProvethVerifier {

    function exposedDecodeUnsignedTx(bytes rlpUnsignedTx) returns (
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        address to,
        uint256 value,
        bytes data,
        bool isContractCreation
    ) {
        UnsignedTransaction memory tx = decodeUnsignedTx(rlpUnsignedTx);
        nonce = tx.nonce;
        gasprice = tx.gasprice;
        startgas = tx.startgas;
        to = tx.to;
        value = tx.value;
        data = tx.data;
        isContractCreation = tx.isContractCreation;
        return;
    }

    function exposedDecodeSignedTx(bytes rlpSignedTx) returns (
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        address to,
        uint256 value,
        bytes data,
        uint256 v,
        uint256 r,
        uint256 s,
        bool isContractCreation
    ) {
        SignedTransaction memory tx = decodeSignedTx(rlpSignedTx);
        nonce = tx.nonce;
        gasprice = tx.gasprice;
        startgas = tx.startgas;
        to = tx.to;
        value = tx.value;
        data = tx.data;
        v = tx.v;
        r = tx.r;
        s = tx.s;
        isContractCreation = tx.isContractCreation;
        return;
    }


    function exposedMerklePatriciaCompactDecode(bytes compact) returns (bytes nibbles) {
        return merklePatriciaCompactDecode(compact);
    }

    // function exposedValidateMPTProof(
    //     bytes32 rootHash,
    //     bytes mptPath,
    //     bytes stackIndexes,
    //     RLP.RLPItem[] stack
    // ) returns (bool valid, bytes value) {
    //     bytes memory memValue;
    //     (valid, memValue) = validateMPTProof(
    //         rootHash,
    //         mptPath,
    //         stackIndexes,
    //         stack);
    //     if (valid) {
    //         return (valid, memValue);
    //     } else {
    //         return (valid, new bytes(0));
    //     }
    // }

    function exposedSharedPrefixLength(uint xsOffset, bytes xs, bytes ys) returns (uint) {
        return sharedPrefixLength(xsOffset, xs, ys);
    }

    function exposedIsPrefix(bytes prefix, bytes full) returns (bool) {
        return isPrefix(prefix, full);
    }
}
