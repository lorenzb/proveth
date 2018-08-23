pragma solidity ^0.4.11;

import "./RLP.sol";

contract ProvethVerifier {
    using RLP for RLP.RLPItem;
    using RLP for RLP.Iterator;
    using RLP for bytes;

    uint256 constant TX_ROOT_HASH_INDEX = 4;

    struct Transaction {
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        bytes to;
        uint256 value;
        bytes data;
        uint256 v;
        uint256 r;
        uint256 s;
    }

    function decodeAndHashUnsignedTx(bytes rlpUnsignedTx) public view returns (
        bool valid,
        bytes32 sigHash,
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        bytes to,
        uint256 value,
        bytes data
    ) {
        sigHash = keccak256(rlpUnsignedTx);
        valid = true;
        RLP.RLPItem[] memory fields = rlpUnsignedTx.toRLPItem().toList();
        require(fields.length == 6);
        nonce = fields[0].toUint();
        gasprice = fields[1].toUint();
        startgas = fields[2].toUint();
        to = fields[3].toData();
        value = fields[4].toUint();
        data = fields[5].toData();
    }

    // TODO(lorenzb): This should actually be pure, not view. Probably because
    // wrong declarations in RLP.sol.
    function decodeTx(bytes rlptx) internal view returns (Transaction memory t) {
        RLP.RLPItem[] memory fields = rlptx.toRLPItem().toList();
        t = Transaction(
            fields[0].toUint(),
            fields[1].toUint(),
            fields[2].toUint(),
            fields[3].toData(),
            fields[4].toUint(),
            fields[5].toData(),
            fields[6].toUint(),
            fields[7].toUint(),
            fields[8].toUint()
        );
    }

    function decodeNibbles(bytes compact, uint skipNibbles) returns (bytes memory nibbles) {
        require(compact.length > 0);

        uint length = compact.length * 2;
        require(skipNibbles <= length);
        length -= skipNibbles;

        nibbles = new bytes(length);
        uint nibblesLength = 0;

        for (uint i = skipNibbles; i < skipNibbles + length; i += 1) {
            if (i % 2 == 0) {
                nibbles[nibblesLength] = bytes1((uint8(compact[i/2]) >> 4) & 0xF);
            } else {
                nibbles[nibblesLength] = bytes1((uint8(compact[i/2]) >> 0) & 0xF);
            }
            nibblesLength += 1;
        }

        assert(nibblesLength == nibbles.length);
    }

    function merklePatriciaCompactDecode(bytes compact) returns (bytes memory nibbles) {
        require(compact.length > 0);
        uint first_nibble = uint8(compact[0]) >> 4 & 0xF;
        uint skipNibbles;
        if (first_nibble == 0) {
            skipNibbles = 2;
        } else if (first_nibble == 1) {
            skipNibbles = 1;
        } else if (first_nibble == 2) {
            skipNibbles = 2;
        } else if (first_nibble == 3) {
            skipNibbles = 1;
        } else {
            // Not supposed to happen!
            require(false);
        }
        return decodeNibbles(compact, skipNibbles);
    }

    function exposeMerklePatriciaCompactDecode(bytes compact) returns (bytes nibbles) {
        return merklePatriciaCompactDecode(compact);
    }

    function isPrefix(bytes prefix, bytes full) returns (bool) {
        if (prefix.length > full.length) {
            return false;
        }

        for (uint i = 0; i < prefix.length; i += 1) {
            if (prefix[i] != full[i]) {
                return false;
            }
        }

        return true;
    }

    function sharedPrefixLength(uint xsOffset, bytes xs, bytes ys) returns (uint) {
        for (uint i = 0; i + xsOffset < xs.length && i < ys.length; i++) {
            if (xs[i + xsOffset] != ys[i]) {
                return i;
            }
        }
        return i;
    }

    struct Proof {
        uint256 kind;
        bytes rlpBlockHeader;
        bytes32 txRootHash;
        bytes rlpTxIndex;
        uint txIndex;
        bytes mptPath;
        bytes stackIndexes;
        RLP.RLPItem[] stack;
    }

    function decodeProofBlob(bytes proofBlob) internal returns (Proof memory proof) {
        RLP.RLPItem[] memory proofFields = proofBlob.toRLPItem().toList();
        proof = Proof(
            proofFields[0].toUint(),
            proofFields[1].toBytes(),
            proofFields[1].toList()[TX_ROOT_HASH_INDEX].toBytes32(),
            proofFields[2].toBytes(),
            proofFields[2].toUint(),
            proofFields[3].toData(),
            proofFields[4].toData(),
            proofFields[5].toList()
        );
    }

    uint8 constant public TX_PROOF_RESULT_INVALID = 0;
    uint8 constant public TX_PROOF_RESULT_PRESENT = 1;
    uint8 constant public TX_PROOF_RESULT_ABSENT = 2;
    function txProof(
        bytes32 blockHash,
        bytes proofBlob
    ) returns (
        uint8 result, // see TX_PROOF_RESULT_*
        uint256 index,
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        bytes to, // 20 byte address for "regular" tx,
                  // empty for contract creation tx
        uint256 value,
        bytes data,
        uint256 v,
        uint256 r,
        uint256 s
    ) {
        Transaction memory t;
        (result, index, t) = validateTxProof(blockHash, proofBlob);
        nonce = t.nonce;
        gasprice = t.gasprice;
        startgas = t.startgas;
        to = t.to;
        value = t.value;
        data = t.data;
        v = t.v;
        r = t.r;
        s = t.s;
    }

    function validateTxProof(
        bytes32 blockHash,
        bytes proofBlob
    ) internal returns (uint8 result, uint256 index, Transaction memory t) {
        result = TX_PROOF_RESULT_INVALID;
        index = 0;
        Proof memory proof = decodeProofBlob(proofBlob);
        require(proof.stack.length == proof.stackIndexes.length);
        if (proof.kind != 1) {
            return;
        }

        if (keccak256(proof.rlpBlockHeader) != blockHash) {
            return;
        }

        // TODO(lorenzb): Validate structure of indexes, e.g. last index == 2 if we have a Leaf, etc...

        bool valid;
        bytes memory rlpTx;
        (valid, rlpTx) = validateMPTProof(proof.txRootHash, proof.mptPath, proof.stackIndexes, proof.stack);
        if (!valid) {
            return;
        }

        bytes memory mptKeyNibbles = decodeNibbles(proof.rlpTxIndex, 0);
        if (rlpTx.length == 0) {
            // empty node
            if (isPrefix(proof.mptPath, mptKeyNibbles)) {
                result = TX_PROOF_RESULT_ABSENT;
                index = proof.txIndex;
                return;
            } else {
                return;
            }
        } else {
            // tx
            if (isPrefix(proof.mptPath, mptKeyNibbles) && proof.mptPath.length == mptKeyNibbles.length) {
                result = TX_PROOF_RESULT_PRESENT;
                index = proof.txIndex;
                t = decodeTx(rlpTx);
                return;
            } else {
                return;
            }
        }
    }

    function mptHashHash(bytes memory input) internal returns (bytes32) {
        if (input.length < 32) {
            return keccak256(input);
        } else {
            return keccak256(keccak256(input));
        }
    }

    function validateMPTProof(
        bytes32 rootHash,
        bytes mptPath,
        bytes stackIndexes,
        RLP.RLPItem[] memory stack
    ) internal returns (bool valid, bytes memory value) {
        assert(stackIndexes.length == stack.length);

        valid = false;
        uint mptPathOffset = 0;

        bytes32 nodeHashHash;
        bytes memory rlpNode;
        RLP.RLPItem[] memory node;

        RLP.RLPItem memory rlpValue;

        if (stack.length == 0) {
            // Root hash of empty tx trie
            valid = (rootHash == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421);
            value = new bytes(0);
            return;
        }

        for (uint i = 0; i < stack.length; i++) {

            // We use the fact that an rlp encoded list consists of some
            // encoding of its length plus the concatenation of its
            // *rlp-encoded* items.
            rlpNode = stack[i].toBytes();
            if (i == 0 && rootHash != keccak256(rlpNode)) {
                return;
            }
            if (i != 0 && nodeHashHash != mptHashHash(rlpNode)) {
                return;
            }
            node = stack[i].toList();

            if (node.length == 2) {
                // Extension or Leaf node
                bytes memory nodePath = merklePatriciaCompactDecode(node[0].toData());

                uint prefixLength = sharedPrefixLength(mptPathOffset, mptPath, nodePath);
                mptPathOffset += prefixLength;

                if (stackIndexes[i] == 0xff) {
                    // proof claims divergent extension or leaf

                    if (i < stack.length - 1) {
                        // divergent node must come last in proof
                        return;
                    }

                    if (prefixLength == nodePath.length) {
                        // node isn't divergent
                        return;
                    }

                    if (mptPathOffset != mptPath.length) {
                        // didn't consume entire mptPath
                        return;
                    }

                    return (true, new bytes(0));
                } else if (stackIndexes[i] == 1) {
                    if (prefixLength != nodePath.length) {
                        // node is divergent
                        return;
                    }

                    if (i < stack.length - 1) {
                        // not last level
                        if (node[uint(stackIndexes[i])].isData()) {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toData());
                        } else {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toBytes());
                        }
                    } else {
                        // didn't consume entire mptPath
                        if (mptPathOffset != mptPath.length) {
                            return;
                        }

                        rlpValue = node[uint(stackIndexes[i])];
                        return (true, rlpValue.toData());
                    }
                } else {
                    // an extension/leaf node only has two fields.
                    return;
                }
            } else if (node.length == 17) {
                // Branch node
                if (stackIndexes[i] < 16) {
                    // advance mptPathOffset
                    if (mptPathOffset >= mptPath.length || mptPath[mptPathOffset] != stackIndexes[i]) {
                        return;
                    }
                    mptPathOffset += 1;

                    if (i < stack.length - 1) {
                        // not last level
                        if (node[uint(stackIndexes[i])].isData()) {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toData());
                        } else {
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toBytes());
                        }
                    } else {
                        // last level
                        // must have an empty hash, everything else is invalid
                        if (node[uint(stackIndexes[i])].toData().length != 0) {
                            return;
                        }

                        if (mptPathOffset != mptPath.length) {
                            // didn't consume entire mptPath
                            return;
                        }

                        return (true, new bytes(0));
                    }
                } else if (stackIndexes[i] == 16) { // we want the value stored in this node
                    if (i < stack.length - 1) {
                        // value must come last in proof
                        return;
                    }

                    if (mptPathOffset != mptPath.length) {
                        // didn't consume entire mptPath
                        return;
                    }

                    rlpValue = node[uint(stackIndexes[i])];
                    return (true, rlpValue.toData());
                } else {
                    throw;
                }
            } else {
                throw;   // This should never happen as we have
                         // already authenticated node at this point.
            }
        }

        // We should never reach this point.
        throw;
    }
}