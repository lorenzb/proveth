pragma solidity ^0.5.0;

import "./Solidity-RLP/contracts/RLPReader.sol";

contract ProvethVerifier {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;

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

    function isEmpty(RLPReader.RLPItem memory item) internal pure returns (bool) {
        if (item.len != 1) {
            return false;
        }
        uint8 b;
        uint memPtr = item.memPtr;
        assembly {
            b := byte(0, mload(memPtr))
        }
        return b == 0x80 /* empty byte string */ || b == 0xc0 /* empty list */;
    }

    function isEmptyBytesequence(RLPReader.RLPItem memory item) internal pure returns (bool) {
        if (item.len != 1) {
            return false;
        }
        uint8 b;
        uint memPtr = item.memPtr;
        assembly {
            b := byte(0, mload(memPtr))
        }
        return b == 0x80 /* empty byte string */;
    }


    function decodeUnsignedTx(bytes memory rlpUnsignedTx) internal pure returns (UnsignedTransaction memory t) {
        RLPReader.RLPItem[] memory fields = rlpUnsignedTx.toRlpItem().toList();
        require(fields.length == 6);
        address potentialAddress;
        bool isContractCreation;
        if(isEmpty(fields[3])) {
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
            fields[5].toBytes(), // data
            isContractCreation
        );
    }

    function decodeSignedTx(bytes memory rlpSignedTx) internal pure returns (SignedTransaction memory t) {
        RLPReader.RLPItem[] memory fields = rlpSignedTx.toRlpItem().toList();
        address potentialAddress;
        bool isContractCreation;
        if(isEmpty(fields[3])) {
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
            fields[5].toBytes(),
            fields[6].toUint(),
            fields[7].toUint(),
            fields[8].toUint(),
            isContractCreation
        );
    }

    function decodeNibbles(bytes memory compact, uint skipNibbles) internal pure returns (bytes memory nibbles) {
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

    function merklePatriciaCompactDecode(bytes memory compact) internal pure returns (bool isLeaf, bytes memory nibbles) {
        require(compact.length > 0);
        uint first_nibble = uint8(compact[0]) >> 4 & 0xF;
        uint skipNibbles;
        if (first_nibble == 0) {
            skipNibbles = 2;
            isLeaf = false;
        } else if (first_nibble == 1) {
            skipNibbles = 1;
            isLeaf = false;
        } else if (first_nibble == 2) {
            skipNibbles = 2;
            isLeaf = true;
        } else if (first_nibble == 3) {
            skipNibbles = 1;
            isLeaf = true;
        } else {
            // Not supposed to happen!
            revert();
        }
        return (isLeaf, decodeNibbles(compact, skipNibbles));
    }

    function sharedPrefixLength(uint xsOffset, bytes memory xs, bytes memory ys) internal pure returns (uint) {
        uint i;
        for (i = 0; i + xsOffset < xs.length && i < ys.length; i++) {
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
        bytes mptKey;
        RLPReader.RLPItem[] stack;
    }

    function decodeProofBlob(bytes memory proofBlob) internal pure returns (Proof memory proof) {
        RLPReader.RLPItem[] memory proofFields = proofBlob.toRlpItem().toList();
        bytes memory rlpTxIndex = proofFields[2].toRlpBytes();
        proof = Proof(
            proofFields[0].toUint(),
            proofFields[1].toRlpBytes(),
            bytes32(proofFields[1].toList()[TX_ROOT_HASH_INDEX].toUint()),
            rlpTxIndex,
            proofFields[2].toUint(),
            decodeNibbles(rlpTxIndex, 0),
            proofFields[3].toList()
        );
    }

    uint8 constant public TX_PROOF_RESULT_PRESENT = 1;
    uint8 constant public TX_PROOF_RESULT_ABSENT = 2;

    function txProof(
        bytes32 blockHash,
        bytes memory proofBlob
    ) public pure returns (
        uint8 result, // see TX_PROOF_RESULT_*
        uint256 index,
        uint256 nonce,
        uint256 gasprice,
        uint256 startgas,
        address to, // 20 byte address for "regular" tx,
                    // empty for contract creation tx
        uint256 value,
        bytes memory data,
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
        bytes memory proofBlob
    ) internal pure returns (uint8 result, uint256 index, SignedTransaction memory t) {
        result = 0;
        index = 0;
        Proof memory proof = decodeProofBlob(proofBlob);
        if (proof.kind != 1) {
            revert();
        }

        if (keccak256(proof.rlpBlockHeader) != blockHash) {
            revert();
        }


        bytes memory rlpTx = validateMPTProof(proof.txRootHash, proof.mptKey, proof.stack);

        if (rlpTx.length == 0) {
            // empty node
            return (
                TX_PROOF_RESULT_ABSENT,
                proof.txIndex,
                t
            );
        } else {
            return (
                TX_PROOF_RESULT_PRESENT,
                proof.txIndex,
                decodeSignedTx(rlpTx)
            );
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
    /// @param mptKey is the key (consisting of nibbles) of the node whose
    ///        inclusion/exclusion we are proving.
    /// @param stack is the stack of MPT nodes (starting with the root) that
    ///        need to be traversed during verification.
    /// @return value whose inclusion is proved or an empty byte array for
    ///         a proof of exclusion
    function validateMPTProof(
        bytes32 rootHash,
        bytes memory mptKey,
        RLPReader.RLPItem[] memory stack
    ) internal pure returns (bytes memory value) {
        uint mptKeyOffset = 0;

        bytes32 nodeHashHash;
        bytes memory rlpNode;
        RLPReader.RLPItem[] memory node;

        RLPReader.RLPItem memory rlpValue;

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
            rlpNode = stack[i].toRlpBytes();
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

                bool isLeaf;
                bytes memory nodeKey;
                (isLeaf, nodeKey) = merklePatriciaCompactDecode(node[0].toBytes());

                uint prefixLength = sharedPrefixLength(mptKeyOffset, mptKey, nodeKey);
                mptKeyOffset += prefixLength;

                if (prefixLength < nodeKey.length) {
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

                    // Sanity check
                    if (i < stack.length - 1) {
                        // divergent node must come last in proof
                        revert();
                    }

                    return new bytes(0);
                }

                if (isLeaf) {
                    // Sanity check
                    if (i < stack.length - 1) {
                        // leaf node must come last in proof
                        revert();
                    }

                    if (mptKeyOffset < mptKey.length) {
                        return new bytes(0);
                    }

                    rlpValue = node[1];
                    return rlpValue.toBytes();
                } else { // extension
                    // Sanity check
                    if (i == stack.length - 1) {
                        // shouldn't be at last level
                        revert();
                    }

                    if (!node[1].isList()) {
                        // rlp(child) was at least 32 bytes. node[1] contains
                        // Keccak256(rlp(child)).
                        nodeHashHash = keccak256(node[1].toBytes());
                    } else {
                        // rlp(child) was at less than 32 bytes. node[1] contains
                        // rlp(child).
                        nodeHashHash = keccak256(node[1].toRlpBytes());
                    }
                }
            } else if (node.length == 17) {
                // Branch node

                if (mptKeyOffset != mptKey.length) {
                    // we haven't consumed the entire path, so we need to look at a child
                    uint8 nibble = uint8(mptKey[mptKeyOffset]);
                    mptKeyOffset += 1;
                    if (nibble >= 16) {
                        // each element of the path has to be a nibble
                        revert();
                    }

                    if (isEmptyBytesequence(node[nibble])) {
                        // Sanity
                        if (i != stack.length - 1) {
                            // leaf node should be at last level
                            revert();
                        }

                        return new bytes(0);
                    } else if (!node[nibble].isList()) {
                        nodeHashHash = keccak256(node[nibble].toBytes());
                    } else {
                        nodeHashHash = keccak256(node[nibble].toRlpBytes());
                    }
                } else {
                    // we have consumed the entire mptKey, so we need to look at what's contained in this node.

                    // Sanity
                    if (i != stack.length - 1) {
                        // should be at last level
                        revert();
                    }

                    return node[16].toBytes();
                }
            }
        }
    }
}
