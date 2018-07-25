import collections
import json
import os
import sys
import unittest

from ethereum import utils
from ethereum import config
from ethereum.tools import tester as t
from ethereum.utils import mk_contract_address, checksum_encode
import rlp

from test_utils import rec_hex, rec_bin, deploy_solidity_contract

sys.path.append(os.path.join(os.path.dirname(__file__), '../../offchain'))
import proveth

class TestVerifier(unittest.TestCase):
    def null_address(self):
        return '0x' + '0' * 40

    def assertEqualAddr(self, *args, **kwargs):
        return self.assertEqual(checksum_encode(args[0]), checksum_encode(args[1]), *args[2:], **kwargs)

    def setUp(self):
        config.config_metropolis['BLOCK_GAS_LIMIT'] = 2**60
        self.chain = t.Chain(env=config.Env(config=config.config_metropolis))
        self.chain.mine()

        contract_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        self.verifier_contract = deploy_solidity_contract(
            self.chain,
            {'ProvethVerifier.sol': {'urls': [os.path.join(contract_dir, 'ProvethVerifier.sol')]},
             'RLP.sol': {'urls': [os.path.join(contract_dir, 'RLP.sol')]},
             'ExposedProvethVerifier.sol': {'urls': [os.path.join(contract_dir, 'ExposedProvethVerifier.sol')]},
            },
            contract_dir,
            'ExposedProvethVerifier.sol',
            'ExposedProvethVerifier',
            10**7,
        )

        self.rpc_cache = {}

    def test_sharedPrefixLength(self):
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(0, b'', b'a'),
            0)
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(0, b'b', b'a'),
            0)
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(0, b'b', b''),
            0)
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(0, b'a', b'a'),
            1)
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(0, b'aaac', b'aaab'),
            3)
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(1, b'aaac', b'aaab'),
            2)
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(3, b'aaac', b'aaab'),
            0)
        self.assertEqual(
            self.verifier_contract.exposedSharedPrefixLength(4, b'aaaa', b'aaaa'),
            0)

    def test_isPrefix(self):
        self.assertTrue(
            self.verifier_contract.exposedIsPrefix(b'', b''))
        self.assertFalse(
            self.verifier_contract.exposedIsPrefix(b'a', b''))
        self.assertTrue(
            self.verifier_contract.exposedIsPrefix(b'abc', b'abcdef'))


    def test_decodeAndHashUnsignedTx(self):
        tx = collections.OrderedDict([
            ('nonce', 3),
            ('gasprice', 0x06fc23ac00),
            ('startgas', 0x0494e5),
            ('to', rec_bin('0xb13f6f423781bd1934fc8599782f5e161ce7c816')),
            ('value', 0x2386f26fc10000),
            ('data', rec_bin('0xf435f5a7000000000000000000000000c198eccab3fe1f35e9160b48eb18af7934a13262')),
        ])

        rlp_tx = rlp.encode(list(tx.values()))
        print(rec_hex(utils.sha3(rlp_tx)))

        (valid, sigHash, nonce, gasprice, startgas, to, value, data) = \
            self.verifier_contract.decodeAndHashUnsignedTx(
                rlp_tx
            )
        self.assertTrue(valid)
        self.assertEqual(sigHash, utils.sha3(rlp_tx))
        self.assertEqual(nonce, tx['nonce'])
        self.assertEqual(gasprice, tx['gasprice'])
        self.assertEqual(startgas, tx['startgas'])
        self.assertEqualAddr(to, tx['to'])
        self.assertEqual(value, tx['value'])
        self.assertEqual(data, tx['data'])

    def test_merklePatriciaCompactDecode(self):
        self.assertEqual(
            utils.decode_hex(''),
            self.verifier_contract.exposedMerklePatriciaCompactDecode(utils.decode_hex('00')))
        self.assertEqual(
            utils.decode_hex('00'),
            self.verifier_contract.exposedMerklePatriciaCompactDecode(utils.decode_hex('10')))
        self.assertEqual(
            utils.decode_hex('0102030405'),
            self.verifier_contract.exposedMerklePatriciaCompactDecode(utils.decode_hex('112345')))
        self.assertEqual(
            utils.decode_hex('000102030405'),
            self.verifier_contract.exposedMerklePatriciaCompactDecode(utils.decode_hex('00012345')))
        self.assertEqual(
            utils.decode_hex('000f010c0b08'),
            self.verifier_contract.exposedMerklePatriciaCompactDecode(utils.decode_hex('200f1cb8')))
        self.assertEqual(
            utils.decode_hex('0f010c0b08'),
            self.verifier_contract.exposedMerklePatriciaCompactDecode(utils.decode_hex('3f1cb8')))


    def test_manual1(self):
        # from block 1322230 on ropsten
        proof_blob = utils.decode_hex('f903c101b9021af90217a05b5782c32df715c083da95b805959d4718ec698915a4b0288e325aa346436be1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794fee3a49dc4243fa92019fc4331228043b3c5e825a013a50145091c1b5bae07abe10da88c54c5111c3fbb74fc91074ad2ffec311f6ba00c673fc4822ba97cc737cfa7a839d6f6f755deedb1506490911f710bfa9315bfa00c1fcb2441331ab1abc2e174a7293acce160d0b04f35a4b791bf89e9fd452b10b9010000000000000000200000000000000000000000000010002000000000000000000040000000000000000000000010000000000000000000000040000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000100840c0b580c83142cf68347e7c4830428a184596e599f99d883010606846765746887676f312e382e338664617277696ea06ebda3617b113ba6550d08cb34119f940ddb96b509c62b7d0a8420722329d5b48861ebb9e58c93ac260182000183000101f90198f851a0da42945ae3c75118e89abff39ad566fd0a30b574e5df8ae70ce59d4cc5f19cb180808080808080a0ca85a0d0ed219e8583feadf2dce0a73aa05e7d6a790c32efcc1dd6c901195f168080808080808080f8b180a0e61bb422a77353192ae2b4b29c3773b018da71d1425b2a48cca04d7da9917faba06b46aad90e0a9eeede8f2ad992401e52b3e52ce7d5bf723a48922401d5af95cca0997f63912b72cdf8a907025644e1df51c313015c4e9e51500fa6ffa52241eef4a05ad4d0c46a043da4e1da601955a1d29d5bd3b6c5b2dfc2776c8a898f998af498a0457048648440cf69193e770035a2df6f42ab5a6b8bc4d789a92074dc2beb20918080808080808080808080f89020b88df88b820beb8506fc23ac00832dd5d8943d04303126cd6e75324825455685b028401e0ec280a4e733ca974e6964610000000000000000000000000000000000000000000000000000000029a0f5405ffd54b78fc27dc56c49364ec22ba94c471f4639f052cfe324e3fc05d1d3a041291d64a8cdf499c386fde5bc04a1ca743aa81f65dc59198d29f8d66ee588a5')
        block_hash = utils.decode_hex('51c92d45e39db17e43f0f7333de44c592b504bb8ac24dc3c39135d46655bae4f')
        result, index, nonce, gas_price, gas, to, value, data, v, r, s = self.verifier_contract.txProof(
            block_hash,
            proof_blob,
            startgas=10**6)
        self.assertEqual(result, self.verifier_contract.TX_PROOF_RESULT_PRESENT())
        self.assertEqual(index, 1)


    def test_manual2(self):
        proof_blob = utils.decode_hex('f904ca01b90206f90203a0e7c29816452c474e261b1d02d3bab489df00069892863bc654ddd609b7f7fc4ba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2930b35844a230f00e51431acae96fe543a0347a00272d32e39cf493242e079965942776e1a6492e74532eb25d5ed8f56aab40331a01b0134ed566a1bf54f29bd55929b75139de4450d8bf43d33b02a1b26b4873af6a0b9b5d8d9f58ad6b835be1b1bde2461e809905257c2610329fe94de5109c2cfadb9010003424803034030147969000005008084532a1c8a0020000400000424302c0578310012204d0883204010ca0000401800020448800000909104008110e02b006000060142000000994112c20924a0200002820020002402000801001020004412203000281600200000c1802940080a1c0010a029080410408a0020150400681c32020104600800004400100900032840000285000800209440420209010500800606200010420003050010100064884080000c23a02080c130028054a401080040086402088c0252005c00000000e82000406005824800412011200c2020a0010810000901120010020c08c4a000828440040008a004608950810200c208008887090e046147907c834c4d6b837a11d38379ca58845a709667827331a0915aa3cd5dea74d24e39ffd6acc5da3b2b692d4b3fcc6cc26222b9205fd64b46880eb2c4f807cb14248281828408010802850801010201f902aff90131a08e61195faa58f0c8467b7f62a15ec6122d7f9484021eaf7b9fe372fffde310b8a05b9674e1d977f6a30fc12a9ac35aeecbbe0d49dcc0d8952e5d833539504ca649a05262513c779d4d62f559300126b4a34435923dceadd291ec3e1d4da6d284b8fca0672d7beb02403cbf570f2aa2956d3d6a8be5b928a425ee263e744db509958d06a0cb1005949f6f4f14beeaf39c9ee07fc2cf68fcb804aaecc4168828bb265f3f1ca0d89a971d2813936524ef4e38ee2dd300cf02764bec57845b8c0064118246ab97a014d80d349c773c690ef2711a7c4c916cec6a333594d378d2b6cebf2bff1c9ce2a0a932d14ab39608d22c0ba8a0e2fafa8a9359968f29b34827cff06e3cc5d0fdeea059d69a507142ffd21a40f829f094f283758e8a32b077c8373a6215cc0e0d61328080808080808080f851a0af2178a9930004f22ee1e2eb87f1035e559971de937dc9ae6f6ba7b6640df2a7a0d92a714520fe45d10652c6b429ca037104644bae3fe13edb8e52b2efb645e16a808080808080808080808080808080e218a01bf683031aaa6ef9c75509021a8ba5f4c9eb6f134413d57b2d3ae92699f58d95f891a06b621312dca8604610878ecf0384c9855dd6e388a0d587441be1dedfe2c73804a0530e3712b1763a989ef0b80b5a90619e7b0452069f1cf4ba3be0a7459a8654cca05f174cd7f8bd7be186b9f8127e181be52bb94cc662f36a8ec1fa3c6083db0ec7a0d94d6ab7f87669a948645e2191b193672be0720018f15115e71720140a027f3e80808080808080808080808080f87020b86df86b821935843b9aca00825208944ce3adf23418a3c3f4a61cde1c7057677befd9bf86719a2d5d6e008025a0121772bdbd0945dcfea42152186b9f7ae6d0271fdd6d1777fcadf5383a88336ca021196e93025480173f429c9e9a27c1921dd6c10b3705c30125424285250bd5a5')
        block_hash = utils.decode_hex('23d2df699671ac564b382f5b046e0cf533ebc44ab8e36426cef9d60486c3a220')
        result, index, nonce, gas_price, gas, to, value, data, v, r, s = self.verifier_contract.txProof(
            block_hash,
            proof_blob,
            startgas=10**6)
        self.assertEqual(result, self.verifier_contract.TX_PROOF_RESULT_PRESENT())
        self.assertEqual(index, 130)

    def help_test_entire_block(self, path_to_jsonrpc_response):
        PRESENT = self.verifier_contract.TX_PROOF_RESULT_PRESENT()
        ABSENT = self.verifier_contract.TX_PROOF_RESULT_ABSENT()
        with open(path_to_jsonrpc_response, 'r') as f:
            jsonrpc = json.load(f)
        block_dict = jsonrpc['result']
        for i in range(len(block_dict['transactions']) + 20):
            proof_blob = proveth.generate_proof_blob_from_jsonrpc_response(jsonrpc, i)
            result, index, nonce, gas_price, gas, to, value, data, v, r, s = self.verifier_contract.txProof(
                utils.decode_hex(block_dict['hash']),
                proof_blob,
                startgas=10**7)
            print(i)
            present = i < len(block_dict['transactions'])
            self.assertEqual(result, PRESENT if present else ABSENT)
            self.assertEqual(index, i)
            if present:
                self.assertEqual(nonce, utils.parse_as_int(block_dict['transactions'][i]['nonce']))
                self.assertEqual(gas_price, utils.parse_as_int(block_dict['transactions'][i]['gasPrice']))
                self.assertEqual(gas, utils.parse_as_int(block_dict['transactions'][i]['gas']))
                self.assertEqual(to, utils.normalize_address(block_dict['transactions'][i]['to'] or '', allow_blank=True))
                self.assertEqual(value, utils.parse_as_int(block_dict['transactions'][i]['value']))
                self.assertEqual(data, utils.decode_hex(block_dict['transactions'][i]['input']))
                self.assertEqual(v, utils.parse_as_int(block_dict['transactions'][i]['v']))
                self.assertEqual(r, utils.parse_as_int(block_dict['transactions'][i]['r']))
                self.assertEqual(s, utils.parse_as_int(block_dict['transactions'][i]['s']))
            if i > 0 and i % 100 == 0:
                self.chain.mine()


    def test_mainnet_blocks(self):
        blocks = [
            '0x0b963d785005ee2d25cb078daba5dd5cae1b376707ac53533d8ad638f9cb9659.json',
            '0x23d2df699671ac564b382f5b046e0cf533ebc44ab8e36426cef9d60486c3a220.json',
            '0x2471ea6da13bb9926a988580fae95056ef1610291d3628aca0ef7f91456c9ef4.json',
            '0x829bb7e1211b1f6f85b9944c2ba1a1614a7d7dedebe9e6bd530ca93dae126a16.json',
        ]
        for block in blocks:
            with self.subTest(block=block):
                print(block)
                self.help_test_entire_block(os.path.join('resources', block))


    def test_single_short_transaction(self):
        self.help_test_entire_block('resources/block_with_single_short_transaction.json')

    def test_big_block_with_short_transaction(self):
        self.help_test_entire_block('resources/big_block_with_short_transaction.json')

    def test_txValidate(self):
        block_hash = '0x51c92d45e39db17e43f0f7333de44c592b504bb8ac24dc3c39135d46655bae4f'
        print("Testing Tx validation for tx 0 in (ropsten) block {}"
              .format(block_hash))

        block_header = [
            "0x5b5782c32df715c083da95b805959d4718ec698915a4b0288e325aa346436be1",
            "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
            "0xfee3a49dc4243fa92019fc4331228043b3c5e825",
            "0x13a50145091c1b5bae07abe10da88c54c5111c3fbb74fc91074ad2ffec311f6b",
            "0x0c673fc4822ba97cc737cfa7a839d6f6f755deedb1506490911f710bfa9315bf",
            "0x0c1fcb2441331ab1abc2e174a7293acce160d0b04f35a4b791bf89e9fd452b10",
            "0x00000000000000200000000000000000000000000010002000000000000000000040000000000000000000000010000000000000000000000040000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000100",
            202070028,
            1322230,
            4712388,
            272545,
            1500404127,
            "0xd883010606846765746887676f312e382e338664617277696e",
            "0x6ebda3617b113ba6550d08cb34119f940ddb96b509c62b7d0a8420722329d5b4",
            "0x61ebb9e58c93ac26",
        ]

        self.assertEqual(utils.sha3(rlp.encode(rec_bin(block_header))), rec_bin(block_hash))


        tx = collections.OrderedDict([
            ('nonce', 3),
            ('gasprice', 0x06fc23ac00),
            ('startgas', 0x0494e5),
            ('to', rec_bin('0xb13f6f423781bd1934fc8599782f5e161ce7c816')),
            ('value', 0x2386f26fc10000),
            ('data', rec_bin('0xf435f5a7000000000000000000000000c198eccab3fe1f35e9160b48eb18af7934a13262')),
            ('v', 0x29),
            ('r', 0x4602fcb7ef369fbe1e6d7d1658934a18bcc3b373454fc33dedb53cd9dd0226d2),
            ('s', 0x3a94a58becc2493007a6411b73a2b5c5a58b17b7a79bbb103568cc62b8945961),
        ])

        proof_type = 1
        rlp_block_header = rec_hex(rlp.encode(rec_bin(block_header)))
        mpt_key = "0x80"
        mpt_path = "0x0800"
        stack_indexes = "0x0801"
        stack = [
            ['da42945ae3c75118e89abff39ad566fd0a30b574e5df8ae70ce59d4cc5f19cb1', '', '', '', '', '', '', '', 'ca85a0d0ed219e8583feadf2dce0a73aa05e7d6a790c32efcc1dd6c901195f16', '', '', '', '', '', '', '', ''],
            ['30', rec_hex(rlp.encode(list(tx.values())))],
        ]

        proof_blob = rlp.encode(rec_bin([
            proof_type,
            rlp_block_header,
            mpt_key,
            mpt_path,
            stack_indexes,
            stack,
        ]))

        (result, index, nonce, gasprice, startgas, to, value, data, v, r, s) = \
            self.verifier_contract.txProof(
                rec_bin(block_hash),
                proof_blob,
                startgas=10**6,
            )
        self.assertEqual(result, self.verifier_contract.TX_PROOF_RESULT_PRESENT())
        self.assertEqual(index, 0)
        self.assertEqual(nonce, tx['nonce'])
        self.assertEqual(gasprice, tx['gasprice'])
        self.assertEqual(startgas, tx['startgas'])
        self.assertEqualAddr(to, tx['to'])
        self.assertEqual(value, tx['value'])
        self.assertEqual(data, tx['data'])
        self.assertEqual(v, tx['v'])
        self.assertEqual(r, tx['r'])
        self.assertEqual(s, tx['s'])

if __name__ == '__main__':
    unittest.main()

