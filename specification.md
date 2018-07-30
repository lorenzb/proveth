# Proveth proof-blob format specification

A proveth proof-blob is an [RLP-encoded](https://github.com/ethereum/wiki/wiki/RLP) list.
The first element of the list is a uint that specifies the *kind* of proof the proof-blob represents:
```
[kind, actual proof...]
```

## Proof of transaction inclusion/exclusion

A proof of inclusion proves a statement of the form "the given transaction is present at the given index in the given block". A proof of exclusion proves a statement of the form "there is no transaction at the given index in the given block".

A proof consists of 6 elements:
1. The *kind* is always `1`.
2. consensus block header, consisting of [hash of previous block, uncles hash, miner address, state root hash, transactions root hash, receipts root hash, logs bloom filter, difficulty, number, gas limit, gas used, timestamp, extra data, mix hash, nonce].
3. (zero-based) transaction index
4. path in the Merkle-Patricia-Trie. Since Merkle-Patricia-Tries are hexary, each element of the path is in the interval [0;15]. For a proof of inclusion this is the RLP-encoded transaction index split into nibbles. For a proof of exclusion, it is the longest prefix of the RLP-encoded transaction index split into nibbles that is present as a path in the tree.
5. list of indexes into (6)
6. list of Merkle-Patricia-Trie nodes

Examples:

