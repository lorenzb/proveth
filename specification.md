# Proveth proof-blob format specification

#### Table of Contents

* [Proof kind](#proof-kind)
* [Proof of transaction inclusion/exclusion](#proof-of-transaction-inclusion-exclusion)
  * [Examples](#examples)

<hr>

## Proof kind

Every proveth proof-blob is an [RLP-encoded](https://github.com/ethereum/wiki/wiki/RLP) list.
The initial element of the list is a uint that specifies the *kind* of proof the proof-blob represents:
```
[kind, actual proof...]
```

## Proof of transaction inclusion/exclusion

A proof of inclusion proves a statement of the form "the given transaction is present at the given index in the given block". A proof of exclusion proves a statement of the form "there is no transaction at the given index in the given block".

A proof consists of 6 elements:
- 0: *kind* always equals `1` for this kind of proof
- 1: *consensus block header*, consisting of
   ```
   [<hash of previous block>,
    <uncles hash>,
    <miner address>,
    <state root hash>,
    <transactions root hash>,
    <receipts root hash>,
    <logs bloom filter>,
    <difficulty>,
    <number>,
    <gas limit>,
    <gas used>,
    <timestamp>,
    <extra data>,
    <mix hash>,
    <nonce>]
   ```
- 2: *transaction index* (zero-based)
- 3: *Merkle-Patricia-Trie path*. Since Merkle-Patricia-Tries are hexary, each element of the path is in the interval `[0;15]`. For a proof of inclusion, the path is the RLP-encoded transaction index split into nibbles. For a proof of exclusion, the path is the longest prefix of the RLP-encoded transaction index split into nibbles that is present as a path in the tree.
- 4: list of indexes into (6).
- 5: *Merkle-Patricia-Trie nodes* on the path to the transaction. Each node is a list of length 2 (for *extension* and *leaf* nodes) or a list of length 17 (for *branch* nodes).

### Examples

For better readability, we hex-encode all bytestrings in the examples below.

**Transaction 0 of block 5000000 (mainnet)**

This is proof-blob for transaction 0 of block 5000000 on the mainnet:
```
'f9039c01f90204a0cae4df80f5862e4321690857eded0d8a40136dafb8155453920bade5bd0c46c0a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2930b35844a230f00e51431acae96fe543a0347a06092dfd6bcdd375764d8718c365ce0e8323034da3d3b0c6d72cf7304996b86ada091dfce7cc2174482b5ebcf6f4beedce854641982eadb1a8cf538e3206abf7836a06db67db55d5d972c59646a3bda26a39422e71fe400e4cdf9eb7f5c09b0efa7d0b901008584009c4dd8101162295d8604b1850200788d4c81f39044821155049d2c036a8a00d07f2a10383180984400b0290ba00293400c1d414a5018104a010220101909b918c601251215109755b90003c6a2c23490829e319a506281d9641ac39a840d3aa03e4a287900e0c09641594409a2010543016e966382c02040754030430e2d708316ec64008f0c0100c713b51f8004005bd48980143e08b22bf2262365b8b2658804a560f1028207666d10288144a5a14609a5bcb221280b13da2f4c8800d8422cc27126a46a04f08c00ca9004081d65cc75d10c62862256118481d2e881a993780808e0a00086e321a4602cb214c0044215281c2ccbca824aca00824a8087090c21c56929b2834c4b40837a121d8379fac5845a70760d83743132a094cd4e844619ee20989578276a0a9046877d569d37ba076bf2e8e34f76189dea884617a20003ba3f2580820800820801f9018af90111a0915214954ddbb2b08a9d9de48b2bc31289d3bda55b8f017242f376ff8df56b93a00106fad9e6c0d6c92e84893ba3c26aba93b4e2a1ab3fa52587a6946b7eedebada074fd2bf3665a2576317a74c0215cd4ac19ee0305191df1ae5f5eaa6788c2a9a9a04157e0398ade02f9acf5e4183d5c554af0e39387b7f5c4da6990b3df177ddd32a013e1c573e8e8f09e3d23d30ccfccbafd4ef9666f7df578999bdc5b9c65bdcc80a041a8eb6c4616c8e12c56a6fafbe9013478e14bce6afad04f9b28f47bdcb5373aa09c08f2a7050bdd3e0d6922ff9c8ce801436afcd078a79df6ffae267a2a755b0b80a012e7ff44f271d1f5968b23a258b21f703cacfe3061e0fafe9ea04b810537a6068080808080808080f87430b871f86f820fef851f3305bc008301d8a89488a690553913a795c3c668275297635b903a29e5882c250d42400204008025a05df5034c46551b630553201581bd690e021c13b3134f37d14eb19ea971292a39a04f263a9ef7b6e6d18d1b6c120f051e51aa737e12aabcf9466377779eb60656a9'
```
When we RLP-decode it, we get the following:
```
[
	# kind
	1,
	# consensus block header
	['cae4df80f5862e4321690857eded0d8a40136dafb8155453920bade5bd0c46c0', '1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347', 'b2930b35844a230f00e51431acae96fe543a0347', '6092dfd6bcdd375764d8718c365ce0e8323034da3d3b0c6d72cf7304996b86ad', '91dfce7cc2174482b5ebcf6f4beedce854641982eadb1a8cf538e3206abf7836', '6db67db55d5d972c59646a3bda26a39422e71fe400e4cdf9eb7f5c09b0efa7d0', '8584009c4dd8101162295d8604b1850200788d4c81f39044821155049d2c036a8a00d07f2a10383180984400b0290ba00293400c1d414a5018104a010220101909b918c601251215109755b90003c6a2c23490829e319a506281d9641ac39a840d3aa03e4a287900e0c09641594409a2010543016e966382c02040754030430e2d708316ec64008f0c0100c713b51f8004005bd48980143e08b22bf2262365b8b2658804a560f1028207666d10288144a5a14609a5bcb221280b13da2f4c8800d8422cc27126a46a04f08c00ca9004081d65cc75d10c62862256118481d2e881a993780808e0a00086e321a4602cb214c0044215281c2ccbca824aca00824a80', '090c21c56929b2', '4c4b40', '7a121d', '79fac5', '5a70760d', '743132', '94cd4e844619ee20989578276a0a9046877d569d37ba076bf2e8e34f76189dea', '4617a20003ba3f25'],
	# transaction index
	0,
	# Merkle-Patricia-Trie path, split_nibbles(rlp_encode(0)) = split_nibbles(0x80) = 0x0800
	'0800',
	# Node indexes into the nodes list (next element of this list)
	'0801',
	# Nodes on path to transaction
	[
		# Root node in the transaction Merkle-Patricia-Trie (this is a "branch node")
		['915214954ddbb2b08a9d9de48b2bc31289d3bda55b8f017242f376ff8df56b93', '0106fad9e6c0d6c92e84893ba3c26aba93b4e2a1ab3fa52587a6946b7eedebad', '74fd2bf3665a2576317a74c0215cd4ac19ee0305191df1ae5f5eaa6788c2a9a9', '4157e0398ade02f9acf5e4183d5c554af0e39387b7f5c4da6990b3df177ddd32', '13e1c573e8e8f09e3d23d30ccfccbafd4ef9666f7df578999bdc5b9c65bdcc80', '41a8eb6c4616c8e12c56a6fafbe9013478e14bce6afad04f9b28f47bdcb5373a', '9c08f2a7050bdd3e0d6922ff9c8ce801436afcd078a79df6ffae267a2a755b0b', '', '12e7ff44f271d1f5968b23a258b21f703cacfe3061e0fafe9ea04b810537a606', '', '', '', '', '', '', '', ''],
		# 1st child of root node in the transaction Merkle-Patricia-Trie (this is a "leaf node")
		['30', 'f86f820fef851f3305bc008301d8a89488a690553913a795c3c668275297635b903a29e5882c250d42400204008025a05df5034c46551b630553201581bd690e021c13b3134f37d14eb19ea971292a39a04f263a9ef7b6e6d18d1b6c120f051e51aa737e12aabcf9466377779eb60656a9']
	]
]
```
