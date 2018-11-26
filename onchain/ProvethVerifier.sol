pragma solidity ^0.4.11;

import "./RLP.sol";

contract ProvethVerifier {
    using RLP for RLP.RLPItem;
    using RLP for RLP.Iterator;
    using RLP for bytes;

    uint256 constant TX_ROOT_HASH_INDEX = 4;

    struct UnsignedTransaction {
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        address to;
        uint256 value;
        bytes data;
        bool isContractCreation;
    }

    struct SignedTransaction {
        uint256 nonce;
        uint256 gasprice;
        uint256 startgas;
        address to;
        uint256 value;
        bytes data;
        uint256 v;
        uint256 r;
        uint256 s;
        bool isContractCreation;
    }

    function decodeUnsignedTx(bytes rlpUnsignedTx) internal view returns (UnsignedTransaction memory t) {
        RLP.RLPItem[] memory fields = rlpUnsignedTx.toRLPItem().toList();
        require(fields.length == 6);
        address potentialAddress;
        bool isContractCreation;
        if(fields[3].isEmpty()) {
            potentialAddress = 0x0000000000000000000000000000000000000000;
            isContractCreation = true;
        } else {
            potentialAddress = fields[3].toAddress();
            isContractCreation = false;
        }
        t = UnsignedTransaction(
            fields[0].toUint(), // nonce
            fields[1].toUint(), // gasprice
            fields[2].toUint(), // startgas
            potentialAddress,   // to
            fields[4].toUint(), // value
            fields[5].toData(), // data
            isContractCreation
        );
    }

    // TODO(lorenzb): This should actually be pure, not view. Probably because
    // wrong declarations in RLP.sol.
    function decodeSignedTx(bytes rlpSignedTx) internal view returns (SignedTransaction memory t) {
        RLP.RLPItem[] memory fields = rlpSignedTx.toRLPItem().toList();
        address potentialAddress;
        bool isContractCreation;
        if(fields[3].isEmpty()) {
            potentialAddress = 0x0000000000000000000000000000000000000000;
            isContractCreation = true;
        } else {
            potentialAddress = fields[3].toAddress();
            isContractCreation = false;
        }
        t = SignedTransaction(
            fields[0].toUint(),
            fields[1].toUint(),
            fields[2].toUint(),
            potentialAddress,
            fields[4].toUint(),
            fields[5].toData(),
            fields[6].toUint(),
            fields[7].toUint(),
            fields[8].toUint(),
            isContractCreation
        );
    }

    function decodeNibbles(bytes compact, uint skipNibbles) internal pure returns (bytes memory nibbles) {
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

    function merklePatriciaCompactDecode(bytes compact) internal pure returns (bytes memory nibbles) {
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
            revert();
        }
        return decodeNibbles(compact, skipNibbles);
    }

    function isPrefix(bytes prefix, bytes full) internal pure returns (bool) {
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

    function sharedPrefixLength(uint xsOffset, bytes xs, bytes ys) internal pure returns (uint) {
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

    function decodeProofBlob(bytes proofBlob) internal view returns (Proof memory proof) {
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

    uint8 constant public TX_PROOF_RESULT_PRESENT = 1;
    uint8 constant public TX_PROOF_RESULT_ABSENT = 2;

    function txProof(
        bytes32 blockHash,
        bytes proofBlob
    ) public returns (
        uint8 result, // see TX_PROOF_RESULT_*
        uint256 index,
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        address to, // 20 byte address for "regular" tx,
                  // empty for contract creation tx
        uint256 value,
        bytes data,
        uint256 v,
        uint256 r,
        uint256 s,
        bool isContractCreation
    ) {
        SignedTransaction memory t;
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
        isContractCreation = t.isContractCreation;
    }

    function validateTxProof(
        bytes32 blockHash,
        bytes proofBlob
    ) internal returns (uint8 result, uint256 index, SignedTransaction memory t) {
        result = 0;
        index = 0;
        Proof memory proof = decodeProofBlob(proofBlob);
        require(proof.stack.length == proof.stackIndexes.length);
        if (proof.kind != 1) {
            revert();
        }

        if (keccak256(proof.rlpBlockHeader) != blockHash) {
            revert();
        }

        bytes memory rlpTx = validateMPTProof(proof.txRootHash, proof.mptPath, proof.stackIndexes, proof.stack);

        bytes memory mptKeyNibbles = decodeNibbles(proof.rlpTxIndex, 0);
        if (rlpTx.length == 0) {
            // empty node
            if (isPrefix(proof.mptPath, mptKeyNibbles)) {
                result = TX_PROOF_RESULT_ABSENT;
                index = proof.txIndex;
                return;
            } else {
                revert();
            }
        } else {
            // tx
            if (isPrefix(proof.mptPath, mptKeyNibbles) && proof.mptPath.length == mptKeyNibbles.length) {
                result = TX_PROOF_RESULT_PRESENT;
                index = proof.txIndex;
                t  = decodeSignedTx(rlpTx);
                return;
            } else {
                revert();
            }
        }
    }

    /// @dev Computes the hash of the Merkle-Patricia-Trie hash of the input.
    ///      Merkle-Patricia-Tries use a weird "hash function" that outputs
    ///      *variable-length* hashes: If the input is shorter than 32 bytes,
    ///      the MPT hash is the input. Otherwise, the MPT hash is the
    ///      Keccak-256 hash of the input.
    ///      The easiest way to compare variable-length byte sequences is
    ///      to compare their Keccak-256 hashes.
    /// @param input The byte sequence to be hashed.
    /// @return Keccak-256(MPT-hash(input))
    function mptHashHash(bytes memory input) internal pure returns (bytes32) {
        if (input.length < 32) {
            return keccak256(input);
        } else {
            return keccak256(abi.encodePacked(keccak256(abi.encodePacked(input))));
        }
    }

    /// @dev Validates a Merkle-Patricia-Trie proof.
    ///      If the proof proves the inclusion of some key-value pair in the
    ///      trie, the value is returned. Otherwise, i.e. if the proof proves
    ///      the exclusion of a key from the trie, an empty byte array is
    ///      returned.
    /// @param rootHash is the Keccak-256 hash of the root node of the MPT.
    /// @param mptPath is the path (consisting of nibbles) to the node whose
    ///        inclusion we are proving. For proofs of exclusion, mptPath is
    ///        the longest prefix of the path of the element that is present
    ///        in the tree.
    /// @param stackIndexes is a list of indexes into stack that tell the
    ///        verifier which element of each node to access.
    /// @param stack is the stack of MPT nodes (starting with the root) that
    ///        need to be traversed during verification.
    /// @return value whose inclusion is proved or an empty byte array for
    ///         a proof of exclusion
    function validateMPTProof(
        bytes32 rootHash,
        bytes mptPath,
        bytes stackIndexes,
        RLP.RLPItem[] memory stack
    ) internal returns (bytes memory value) {
        require(stackIndexes.length == stack.length);

        uint mptPathOffset = 0;

        bytes32 nodeHashHash;
        bytes memory rlpNode;
        RLP.RLPItem[] memory node;

        RLP.RLPItem memory rlpValue;

        if (stack.length == 0) {
            // Root hash of empty Merkle-Patricia-Trie
            require(rootHash == 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421);
            return new bytes(0);
        }

        // Traverse stack of nodes starting at root.
        for (uint i = 0; i < stack.length; i++) {

            // We use the fact that an rlp encoded list consists of some
            // encoding of its length plus the concatenation of its
            // *rlp-encoded* items.
            rlpNode = stack[i].toBytes();
            // The root node is hashed with Keccak-256 ...
            if (i == 0 && rootHash != keccak256(rlpNode)) {
                revert();
            }
            // ... whereas all other nodes are hashed with the MPT
            // hash function.
            if (i != 0 && nodeHashHash != mptHashHash(rlpNode)) {
                revert();
            }
            // We verified that stack[i] has the correct hash, so we
            // may safely decode it.
            node = stack[i].toList();

            if (node.length == 2) {
                // Extension or Leaf node

                bytes memory nodePath = merklePatriciaCompactDecode(node[0].toData());

                uint prefixLength = sharedPrefixLength(mptPathOffset, mptPath, nodePath);
                mptPathOffset += prefixLength;

                if (stackIndexes[i] == 0xff) {
                    // Proof claims divergent extension or leaf. (Only
                    // relevant for proofs of exclusion.)
                    // An Extension/Leaf node is divergent iff it "skips" over
                    // the point at which a Branch node should have been had the
                    // excluded key been included in the trie.
                    // Example: Imagine a proof of exclusion for path [1, 4],
                    // where the current node is a Leaf node with
                    // path [1, 3, 3, 7]. For [1, 4] to be included, there
                    // should have been a Branch node at [1] with a child
                    // at 3 and a child at 4.

                    if (i < stack.length - 1) {
                        // divergent node must come last in proof
                        revert();
                    }

                    if (prefixLength == nodePath.length) {
                        // node isn't divergent
                        revert();
                    }

                    if (mptPathOffset != mptPath.length) {
                        // didn't consume entire mptPath
                        revert();
                    }

                    return new bytes(0);
                } else if (stackIndexes[i] == 1) {
                    if (prefixLength != nodePath.length) {
                        // node is divergent, but stack index isn't 0xff.
                        revert();
                    }

                    if (i < stack.length - 1) {
                        // not last level, must be Extension node

                        if (node[uint(stackIndexes[i])].isData()) {
                            // rlp(child) was at least 32 bytes. node[1] contains
                            // Keccak256(rlp(child)).
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toData());
                        } else {
                            // rlp(child) was at less than 32 bytes. node[1] contains
                            // rlp(child).
                            nodeHashHash = keccak256(node[uint(stackIndexes[i])].toBytes());
                        }
                    } else {
                        // last level, must be Leaf node

                        if (mptPathOffset != mptPath.length) {
                            // didn't consume entire mptPath
                            revert();
                        }

                        rlpValue = node[uint(stackIndexes[i])];
                        return rlpValue.toData();
                    }
                } else {
                    // an extension/leaf node only has two fields.
                    revert();
                }
            } else if (node.length == 17) {
                // Branch node

                if (stackIndexes[i] < 16) {
                    // advance mptPathOffset
                    if (mptPathOffset >= mptPath.length || mptPath[mptPathOffset] != stackIndexes[i]) {
                        revert();
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

                        if (node[uint(stackIndexes[i])].toData().length != 0) {
                            // hash isn't empty, but should be since this a proof
                            // of exclusion: we're at the last level of the proof
                            // and the stack index points to one of the child nodes
                            // rather than a value
                            revert();
                        }

                        if (mptPathOffset != mptPath.length) {
                            // didn't consume entire mptPath
                            revert();
                        }

                        return new bytes(0);
                    }
                } else if (stackIndexes[i] == 16) { // we want the value stored in this node
                    if (i < stack.length - 1) {
                        // value must come last in proof
                        revert();
                    }

                    if (mptPathOffset != mptPath.length) {
                        // didn't consume entire mptPath
                        revert();
                    }

                    rlpValue = node[uint(stackIndexes[i])];
                    return rlpValue.toData();
                } else {
                    // index cannot be greater than 16
                    revert();
                }
            } else {
                revert(); // This should never happen as we have
                          // already authenticated node at this point.
            }
        }

        // We should never reach this point.
        revert();
    }
}
