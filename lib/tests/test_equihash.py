import unittest

from ..blockchain import serialize_header, rev_hex, uint256_from_bytes, var_int_read, bfh
from ..equihash import validate_params, is_gbp_valid


class TestEquihash(unittest.TestCase):
    def test_params(self):
        self.assertRaises(ValueError, validate_params, 0, 1)
        self.assertRaises(ValueError, validate_params, 32, 0)

        validate_params(200, 9)
        validate_params(48, 5)

    def test_validate_solution(self):
        header = {
            'merkle_root': 'a0c38df01cd66ccd636c2917472002b90f40c69f177585793167c7c96cc00aea',
            'bits': '207fffff',
            'block_height': 24156,
            'version': 536870912,
            'timestamp': 1520027553,
            'reserved': '00000000000000000000000000000000000000000000000000000000',
            'solution': '269125e395b85db52eafd3b401615665ab0407b725253552073a1b6eefe092c20d02250024',
            'nonce': '0000b0e08b5b13938bcda848f480619e320ceeee9175aef1630e2a6a78f30005',
            'prev_block_hash': '42e56ff42ad233fa1444b4fbb23ea69e85a196ad4e4017292563ecef6561d59b'
        }

        n = 48
        k = 5

        header_bytes = bytes.fromhex(serialize_header(header, False))
        nonce = uint256_from_bytes(bfh(header.get('nonce'))[::-1])
        solution = bfh(header.get('solution'))[::-1]
        offset, length = var_int_read(solution, 0)
        solution = solution[offset:]

        self.assertTrue(is_gbp_valid(header_bytes, nonce, solution, n, k))
