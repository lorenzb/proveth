# Proveth

Ethereum's design [makes heavy use](https://blog.ethereum.org/2015/11/15/merkling-in-ethereum/) of [Merkle trees](https://en.wikipedia.org/wiki/Merkle_tree) enabling *light clients* to interact with the blockchain without having to download full blocks or its complete state.

Ethereum uses its own variant of Merkle trees, called [Merkle Patricia Tries](https://github.com/ethereum/wiki/wiki/Patricia-Tree), which provide a [dictionary](https://en.wikipedia.org/wiki/Associative_array)-like interface and enable the generation and verification of small proofs (logarithmic in the number of items in the dictionary) that a given key-value-pair is present/absent from the dictionary. Ethereum uses Merkle Patricia Tries to store transactions, transactions receipts, and the *state* (all accounts with their balances, code, and storage).

(If you want to learn more about Merkle Patricia Tries, check out the links above and have a look at this [cool visualisation](https://beta.observablehq.com/@cdetrio/ethereum-txtrie-merkle-patricia-trie-viz) Casey built.)

## Project goals

Proveth aims to provide
- a clearly specified format for these proofs;
- a high-quality off-chain proof generator that can connect to an Ethereum node and generate such proofs;
- a high-quality on-chain proof verifier (smart contract) that can verify a proof that a given transaction/state item/... is indeed part of the Ethereum blockchain.

## Project state

Proveth is under active development. We currently support generating and verifying proofs of transaction inclusion/exclusion, i.e. proofs of statements of the form "the transaction `tx` was present/absent at index `i` in the block with blockhash `h`".

We aim to extend this to:
- proofs of transaction receipt inclusion/exclusion
- proofs about the Ethereum state

## Contributing

We welcome contributions. Have a look at any open issues, add more tests/documentation or come up with your own improvements. Before starting work on a large PR, we suggest opening an issue to discuss your approach with the maintainers.

We ❤️ tests & docs, so please write lots of them!

## Authors

Proveth's development was started by the *Submarines* group at the [2018 IC3 Ethereum bootcamp](http://www.initc3.org/events/2018-07-12-IC3-Ethereum-Crypto-Boot-Camp.html):
- Lorenz Breidenbach
- Tyler Kell
- Alex Manuskin
- Casey Detrio
- Derek Chin
- Shayan Eskandari
- Stephane Gosselin
- Yael Doweck

## Acknowledgements

Our design is inspired by [PeaceRelay](https://medium.com/@loiluu/peacerelay-connecting-the-many-ethereum-blockchains-22605c300ad3). Thanks to Nate Rush for answering our questions.