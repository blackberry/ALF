################################################################################
# Name   : BinaryFuzz_test.py
# Author : Tyson Smith & Jesse Schwartzentruber
#
# Copyright 2014 BlackBerry Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################

import BinaryFuzz
import os
import unittest

class BinaryFuzzTests(unittest.TestCase):

    def test_mutate_byte(self):
        o_value = bytearray("Z")[0]
        for fuzz_type in range(0, BinaryFuzz.SINGLE_BYTE_OPS+1):
            self.assertNotEqual(o_value, BinaryFuzz._mutate_byte(o_value, fuzz_type))

    def test_mutate_bytes(self):
        o_value = bytearray("TEST DATA!")
        self.assertNotEqual(o_value, BinaryFuzz._mutate_bytes(o_value))

    def test_BinaryFuzz_fuzz_data(self):
        f = BinaryFuzz.BinaryFileFuzzer()
        test_size = 1000
        test_data = os.urandom(test_size)
        for fuzz_type in range(BinaryFuzz.BINFUZZ_N+1):
            if fuzz_type >= BinaryFuzz.BINFUZZ_N:
                fuzz_type = None
            with self.assertRaises(TypeError):
                f.fuzz_data(test_data, "1")
            fuzz_count, fuzz_data = f.fuzz_data(test_data, 0, fuzz_type=fuzz_type) # no fuzzing
            self.assertEqual(fuzz_count, 0, "Data was fuzzed")
            fuzz_count, fuzz_data = f.fuzz_data(test_data, -1, fuzz_type=fuzz_type)
            self.assertEqual(fuzz_count, 1)
            self.assertNotEqual(test_data, fuzz_data, "Data was not fuzzed (may happen randomly)")
            fuzz_count, fuzz_data = f.fuzz_data(test_data, test_size/100, fuzz_type=fuzz_type)
            self.assertAlmostEqual(fuzz_count, test_size/10, delta=10)
            self.assertNotEqual(test_data, fuzz_data, "Data was not fuzzed")

    def test_BinaryFuzz_disable_fuzz_type(self):
        for fuzz_type in range(BinaryFuzz.BINFUZZ_N):
            f = BinaryFuzz.BinaryFileFuzzer()
            f.disable_fuzz_type(fuzz_type)
            self.assertNotIn(fuzz_type, f.active_fuzz_types)

    def test_BinaryFuzz_set_special_value(self):
        f = BinaryFuzz.BinaryFileFuzzer()
        prev = f.special
        f.set_special_value(prev+1)
        self.assertNotEqual(prev, f.special)

    def test_BinaryFuzz__random_fuzz_type(self):
        f = BinaryFuzz.BinaryFileFuzzer()
        prev = f.active_fuzz_types
        for _ in range(100):
            f._select_active_fuzz_types()
            self.assertNotEqual(f.active_fuzz_types, prev, "Active set matched previous (may happen randomly)")
            prev = f.active_fuzz_types

    def test_BinaryFuzz__select_active_fuzz_types(self):
        f = BinaryFuzz.BinaryFileFuzzer()
        f._select_active_fuzz_types()
        self.assertIsNotNone(f.active_fuzz_types)
        self.assertGreater(f.fuzz_types, 1)
        a_types = f.active_fuzz_types
        success = False
        for _ in range(10):
            f._select_active_fuzz_types()
            if a_types != f.active_fuzz_types:
                success = True
                break
        self.assertTrue(success)

    def test_BinaryFuzz__validate_fuzz_type(self):
        f = BinaryFuzz.BinaryFileFuzzer()
        with self.assertRaises(ValueError):
            f._validate_fuzz_type(-1)
        with self.assertRaises(TypeError):
            f._validate_fuzz_type("1")
        if len(f.fuzz_types):
            f._validate_fuzz_type(f.fuzz_types[0])



suite = unittest.TestLoader().loadTestsFromTestCase(BinaryFuzzTests)
