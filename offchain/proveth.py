import argparse
import json
import sys
from typing import List, Tuple

from ethereum import (
    block,
    transactions,
    utils,
)
import pprint
import requests
import rlp
from trie import HexaryTrie
from trie.constants import (
    BLANK_NODE,
    BLANK_NODE_HASH,
    NODE_TYPE_BLANK,
    NODE_TYPE_LEAF,
    NODE_TYPE_EXTENSION,
    NODE_TYPE_BRANCH,
    BLANK_HASH,
)
from trie.utils.nodes import *
from trie.utils.nibbles import encode_nibbles, decode_nibbles, bytes_to_nibbles
from web3 import Web3

MODULE_DEBUG = False

def rec_hex(x):
    if isinstance(x, list):
        return [rec_hex(elem) for elem in x]
    else:
        return utils.encode_hex(x)

def rec_bin(x):
    if isinstance(x, list):
        return [rec_bin(elem) for elem in x]
    elif isinstance(x, int):
        return x
    elif isinstance(x, str):
        if x.startswith("0x"):
            if len(x) != 2:
                return utils.decode_hex(x[2:])
            else:
                return 0
        else:
            return utils.decode_hex(x)
    elif x is None:
        return 0

def normalize_bytes(hash):
    if isinstance(hash, str):
        if hash.startswith("0x"):
            hash = hash[2:]
        if len(hash) % 2 != 0:
            hash = '0' + hash
        return utils.decode_hex(hash)
    else:
        return bytes(hash)

def get_args():
    parser = argparse.ArgumentParser(
        description="Help",
        formatter_class=argparse.RawTextHelpFormatter)
    # TODO add stuff around adding a block header and then generating proofs of inclusion / exclusion etc etc etc
    parser.add_argument('-b', '--block-hash', required=True,
                        default="", help="Block hash that transaction exists in")
    parser.add_argument('-i', '--transaction-index', required=True, type=int,
                        default="", help="Zero-based index of the transaction in the block "
                                         "(e.g. the third transaction in the block is at index 2)")
    parser.add_argument('-r', '--rpc', required=True,
                        default="", help="URL of web3 rpc node. (e.g. http://localhost:8545)")
    return parser.parse_args()


def rlp_block_header(block_dict: dict):
    b = block.BlockHeader(
        normalize_bytes(block_dict["parentHash"]),
        normalize_bytes(block_dict["sha3Uncles"]),
        utils.normalize_address(block_dict["miner"]),
        normalize_bytes(block_dict["stateRoot"]),
        normalize_bytes(block_dict["transactionsRoot"]),
        normalize_bytes(block_dict["receiptsRoot"]),
        utils.bytes_to_int(normalize_bytes(block_dict["logsBloom"])),
        utils.parse_as_int(block_dict['difficulty']),
        utils.parse_as_int(block_dict['number']),
        utils.parse_as_int(block_dict['gasLimit']),
        utils.parse_as_int(block_dict['gasUsed']),
        utils.parse_as_int(block_dict['timestamp']),
        normalize_bytes(block_dict["extraData"]),
        normalize_bytes(block_dict["mixHash"]),
        normalize_bytes(block_dict["nonce"]),
    )
    assert(normalize_bytes(block_dict["hash"]) == b.hash)
    return rlp.encode(b)

def rlp_transaction(tx_dict: dict):
    # print(tx_dict)
    t = transactions.Transaction(
        utils.parse_as_int(tx_dict['nonce']),
        utils.parse_as_int(tx_dict['gasPrice']),
        utils.parse_as_int(tx_dict['gas']),
        normalize_bytes(tx_dict['to'] or ''),
        utils.parse_as_int(tx_dict['value']),
        utils.decode_hex(tx_dict['input']),
        utils.parse_as_int(tx_dict['v']),
        utils.bytes_to_int(normalize_bytes(tx_dict['r'])),
        utils.bytes_to_int(normalize_bytes(tx_dict['s'])),
    )
    assert(normalize_bytes(tx_dict['hash']) == t.hash)
    return rlp.encode(t)


def generate_proof(mpt, mpt_key_nibbles: bytes):
    assert(all(elem < 16 for elem in mpt_key_nibbles))
    EMPTY = 128
    stack_indexes = []
    mpt_path = []
    stack = []

    def aux(node_hash, mpt_key_nibbles):
        nonlocal stack_indexes
        nonlocal mpt_path
        nonlocal stack

        assert(all(nibble < 16 for nibble in mpt_key_nibbles))
        node = mpt.get_node(node_hash)
        if get_node_type(node) == NODE_TYPE_BLANK:
            if MODULE_DEBUG:
                print("Hit an empty node, returning")
            return
        elif get_node_type(node) == NODE_TYPE_BRANCH:
            if MODULE_DEBUG:
                print("Hit a branch node")
            if mpt_key_nibbles:
                i = mpt_key_nibbles[0]
                stack_indexes.append(i)
                stack.append(node)
                mpt_path.append(i)
                aux(node[i], mpt_key_nibbles[1:])
            else:
                i = 16
                stack_indexes.append(i)
                stack.append(node)
        elif get_node_type(node) in [NODE_TYPE_EXTENSION, NODE_TYPE_LEAF]:
            if MODULE_DEBUG:
                print("Hit an extension/branch node")
            key = extract_key(node)
            prefix, key_remainder, mpt_key_nibbles_remainder = consume_common_prefix(key, mpt_key_nibbles)
            if not key_remainder:
                if MODULE_DEBUG:
                    print("Non-divergent leaf/extension")
                stack_indexes.append(1)
                stack.append(node)
                mpt_path += prefix
                if get_node_type(node) == NODE_TYPE_EXTENSION:
                    aux(node[1], mpt_key_nibbles_remainder)
            else:
                if MODULE_DEBUG:
                    print("Divergent leaf/extension")
                stack_indexes.append(0)
                stack.append(node)
                mpt_path += prefix
        else:
            assert(False)


    root_node = mpt.get_node(mpt.root_hash)
    if get_node_type(root_node) == NODE_TYPE_BLANK:
        if MODULE_DEBUG:
            print("Blank root node")
    else:
        aux(mpt.root_hash, mpt_key_nibbles)

    if MODULE_DEBUG:
        print('key nibbles: ', mpt_key_nibbles)
        print('Stack:       ', rec_hex(stack))
        print('StackIndexes:', stack_indexes)
        print('mpt_path:    ', mpt_path)

    return (mpt_path, stack_indexes, stack)

def generate_proof_blob(block_dict, tx_index):
    rlp_tx_index = rlp.encode(tx_index)
    rlp_header = rlp_block_header(block_dict)

    mpt = HexaryTrie(db={})
    for tx_dict in block_dict["transactions"]:
        key = rlp.encode(utils.parse_as_int(tx_dict['transactionIndex']))
        mpt.set(key, rlp_transaction(tx_dict))

    assert(mpt.root_hash == normalize_bytes(block_dict['transactionsRoot']))

    mpt_key_nibbles = bytes_to_nibbles(rlp_tx_index)
    mpt_path, stack_indexes, stack = generate_proof(mpt, mpt_key_nibbles)

    proof_blob = rlp.encode([
        1, # proof_type
        rlp_header,
        rlp_tx_index,
        bytes(mpt_path),
        bytes(stack_indexes),
        stack,
    ])
    return proof_blob

def generate_proof_blob_from_jsonrpc_response(response, tx_index):
    assert(response['jsonrpc'] == '2.0')
    assert('id' in response)
    return generate_proof_blob(response['result'], tx_index)


def generate_proof_blob_from_jsonrpc(url, block_hash, tx_index):
    request = {
        "jsonrpc":"2.0",
        "method":"eth_getBlockByHash",
        "params":['0x' + utils.encode_hex(block_hash), True],
        "id":1,
    }
    r = requests.post(url, json=request)
    r.raise_for_status()
    return generate_proof_blob_from_jsonrpc_response(r.json(), tx_index)


def main():
    args = get_args()

    proof_blob = generate_proof_blob_from_jsonrpc(args.rpc, utils.decode_hex(args.block_hash), args.transaction_index)

    print("Final Output: ")
    print(rec_hex(proof_blob))
    exit(0)

if __name__ == "__main__":
    main()

