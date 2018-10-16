pragma solidity ^0.4.11;

import "./ProvethVerifier.sol";

contract ExposedProvethVerifier is ProvethVerifier {

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
