################################################################################
# Name   : BinaryFuzz.py
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

import os
import random

from . import file_fixer

################################################################################
# Globals
################################################################################

# Type of fuzzing to perform
# single byte operations
BINFUZZ_RANDOM          = 0
BINFUZZ_INC             = 1
BINFUZZ_DEC             = 2
BINFUZZ_ZERO            = 3
BINFUZZ_MAX             = 4
BINFUZZ_SPECIAL         = 5
BINFUZZ_ONE             = 6
BINFUZZ_NEGATE          = 7
BINFUZZ_XOR             = 8
BINFUZZ_BOUNDARY        = 9
BINFUZZ_ALTERNATE       = 10
# multi byte operations
BINFUZZ_SWAP            = 11
BINFUZZ_DUP             = 12
BINFUZZ_CORRUPT         = 13
BINFUZZ_CORRUPT_INPLACE = 14
BINFUZZ_CHOP            = 15

# add new BINFUZZ types above, and update count below
BINFUZZ_N               = 16
SINGLE_BYTE_OPS         = 10 # up to and including
SPECIAL_BINFUZZ_VALUE   = 0x41

################################################################################
# Functions
################################################################################

def random_binfuzz_type():
    """
    This function will return a randomly chosen fuzz_type from ``BINFUZZ_*``.
    """
    return randint(0, BINFUZZ_N-1)


# takes an integer argument, returns an integer
def _mutate_byte(b, fuzz_type, special=SPECIAL_BINFUZZ_VALUE):
    """
    This function applies the given *fuzz_type* to the input byte, *b*. *fuzz_type*
    is one of the ``BINFUZZ_*`` constants.
    The result is a fuzzed byte value. Both input and result are integer values
    between 0 and 255 inclusive.
    """
    if fuzz_type == BINFUZZ_RANDOM:
        result = random.randint(0, 255)
    elif fuzz_type == BINFUZZ_INC:
        result = b + random.randint(1, 10) if random.randint(1, 10) == 1 else b + 1
    elif fuzz_type == BINFUZZ_DEC:
        result = b - random.randint(1, 10) if random.randint(1, 10) == 1 else b - 1
    elif fuzz_type == BINFUZZ_ZERO:
        result = 0
    elif fuzz_type == BINFUZZ_MAX:
        result = 0xFF
    elif fuzz_type == BINFUZZ_SPECIAL:
        result = special
    elif fuzz_type == BINFUZZ_ONE:
        result = 0x1
    elif fuzz_type == BINFUZZ_NEGATE:
        result = ~b
    elif fuzz_type == BINFUZZ_XOR:
        result = b ^ random.choice((0x11, 0x22, 0x33, 0x44, 0x55, 0x88, 0x99, 0xAA,
                                 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80))
    elif fuzz_type == BINFUZZ_BOUNDARY:
        result = (2**random.randint(0, 7)) + random.randint(-2, 0)
    elif fuzz_type == BINFUZZ_ALTERNATE:
        result = random.choice((0xAA, 0x55, 0x0A, 0x05, 0xA0, 0x50, 0x0F, 0xF0))
    else:
        assert False, "Unhandled Fuzz Type: %d" % fuzz_type
    return result & 0xFF

def _mutate_bytes(target_data, special=SPECIAL_BINFUZZ_VALUE):
    """
    This function applies :func:`~alf.fuzz._mutate_byte` to each byte in a given list
    :func:`~_mutate_bytes` returns a list of fuzzed bytes
    """
    return bytearray(_mutate_byte(b, random.randint(0, SINGLE_BYTE_OPS), special) for b in target_data)

################################################################################
# Classes
################################################################################

class BinaryFileFuzzer(object):
    """
    This class is designed to mutate a string of binary data. *fuzz_type* can be one
    of the ``BINFUZZ_*`` constants, or ``None`` to select at random for each mutation.
    *special* will override the default value of 'A' used when :data:`BINFUZZ_SPECIAL` is
    selected. When *fuzz_type* is None, specific fuzz types can be disabled using
    :meth:`~disable_fuzz_type`. *max_corrupt* is used to set the maximum amount of data to
    add/corrupt in a single pass.
    """
    def __init__(self, fuzz_type=None, special=None, max_corrupt=10240):
        if fuzz_type is None:
            self.fuzz_types = list(range(BINFUZZ_N))
        else:
            self._validate_fuzz_type(fuzz_type)
            self.fuzz_types = [fuzz_type]
        self.active_fuzz_types = list(self.fuzz_types)
        if special is None:
            special = SPECIAL_BINFUZZ_VALUE
        self.special = special
        if not isinstance(max_corrupt, int):
            raise TypeError("max_corrupt must be an int not %s" % type(max_corrupt).__name__)
        self.max_corrupt = max_corrupt

    @staticmethod
    def _validate_fuzz_type(fuzz_type):
        if not isinstance(fuzz_type, int):
            raise TypeError("fuzz_type must be an int not %s" % type(fuzz_type).__name__)
        if not (fuzz_type == int(fuzz_type) and 0 <= fuzz_type < BINFUZZ_N):
            raise ValueError("Unknown BinaryFileFuzzer fuzz type: %r" % str(fuzz_type))

    def disable_fuzz_type(self, fuzz_type):
        """
        This method disables the given *fuzz_type* for all future mutations.
        """
        del self.fuzz_types[self.fuzz_types.index(fuzz_type)]
        self.active_fuzz_types = list(self.fuzz_types)

    def set_special_value(self, special):
        """
        This method will set a new special value to be used by :data:`BINFUZZ_SPECIAL`.
        """
        self.special = special

    def _select_active_fuzz_types(self):
        """
        This method is used to randomly disable different fuzz types on a per iteration basis.
        """
        type_count = len(self.fuzz_types)
        if type_count < 2:
            return
        self.active_fuzz_types = random.sample(self.fuzz_types, random.randint(1, type_count))

    def _random_fuzz_type(self):
        """
        This function will return a randomly chosen fuzz type from ``BINFUZZ_*``.
        Any fuzz types disabled by :meth:`~disable_fuzz_type` will be excluded.
        """
        return random.choice(self.active_fuzz_types)

    def fuzz_data(self, file_data, aggression, fuzz_type=None, fix_ext=None):
        """
        This method mutates the given input data using the *aggression* to determine
        how much of the data to mutate.

        Two modes of aggression are supported. If *aggression* is greater than 0, that
        number is the inverse of the number of bytes to mutate as a ratio of the input length
        (ie. filesize/aggression == number of bytes to mutate). Note that in this mode, aggression
        is statistical, so even an *aggression* of 1 will not hit every byte in the input. The other
        mode of aggression is when *aggression* is less than 0. In this case, the magnitude is
        used as the absolute number of bytes to mutate (ie. -1 == 1 mutation, -2 == 2 mutations, etc.).

        *fuzz_type* specifies how bytes will be mutated. A value of None indicates that a random fuzz_type should
        be used for each byte mutated.

        *fix_ext* is the optional extension of the original file, in which case the data will be filtered
        through :func:`~alf.fuzz.auto_fix` after mutation.

        :meth:`~fuzz_data` returns a tuple containing the number of bytes mutated, and the string of mutated binary data.
        """
        if not isinstance(aggression, int):
            raise TypeError("aggression must be an int not %s" % type(aggression).__name__)
        if not aggression:
            return 0, file_data
        if fuzz_type is not None:
            self._validate_fuzz_type(fuzz_type)
        file_len = len(file_data)
        if aggression > 0:
            bytes_to_fuzz = max(file_len // aggression, 1)
        else:
            bytes_to_fuzz = -aggression
        if file_len < 1:
            bytes_to_fuzz = 0
        bytes_fuzzed = 0
        fuzzed_data = bytearray(file_data)
        req_fuzz_type = fuzz_type
        if req_fuzz_type is None:
            self._select_active_fuzz_types()

        while bytes_fuzzed < bytes_to_fuzz:
            work_left = bytes_to_fuzz - bytes_fuzzed
            if req_fuzz_type is None:
                fuzz_type = self._random_fuzz_type()
            addr = random.randint(0, file_len-1)
            if fuzz_type == BINFUZZ_SWAP:
                if bytes_to_fuzz == 1:
                    # This copies one byte over another.
                    fuzzed_data[addr] = fuzzed_data[random.randint(0, file_len-1)]
                    bytes_fuzzed += 1
                else:
                    # This swaps two chunks. The number of bytes fuzzed is twice the chunk size.
                    addr2 = random.randint(0, file_len-1)
                    addr_low = min(addr, addr2)
                    addr_high = max(addr, addr2)
                    chunk_size = min(addr_high-addr_low, file_len-addr_high, 1+work_left/2)
                    # pylint: disable=W0311
                    (
                        fuzzed_data[addr_low:addr_low+chunk_size],
                        fuzzed_data[addr_high:addr_high+chunk_size]
                    ) = (
                        fuzzed_data[addr_high:addr_high+chunk_size],
                        fuzzed_data[addr_low:addr_low+chunk_size]
                    )
                    bytes_fuzzed += 2 * chunk_size
            elif fuzz_type == BINFUZZ_DUP:
                n = min(self.max_corrupt, file_len - addr, bytes_to_fuzz - bytes_fuzzed)
                n = random.randint(1, random.randint(1, n)) # favor smaller numbers
                fuzzed_data[addr:addr] = fuzzed_data[addr:addr+n]
                bytes_fuzzed += n
            elif fuzz_type == BINFUZZ_CORRUPT:
                # WARNING: this can modify the file size
                n = min(self.max_corrupt, bytes_to_fuzz - bytes_fuzzed)
                n = random.randint(1, random.randint(1, n)) # favor smaller numbers
                fuzzed_data[addr:addr] = os.urandom(n)
                bytes_fuzzed += n
            elif fuzz_type == BINFUZZ_CORRUPT_INPLACE:
                n = min(self.max_corrupt, file_len - addr, bytes_to_fuzz - bytes_fuzzed)
                if n > 2:
                    n = random.randint(1, random.randint(2, n)) # favor smaller numbers
                fuzzed_data[addr:addr+n] = _mutate_bytes(fuzzed_data[addr:addr+n], self.special)
                bytes_fuzzed += n
            elif fuzz_type == BINFUZZ_CHOP:
                # WARNING: this can modify the file size
                n = min(file_len - addr, bytes_to_fuzz - bytes_fuzzed, 64)
                n = random.randint(1, random.randint(1, n)) # favor smaller numbers
                del fuzzed_data[addr:addr+n]
                bytes_fuzzed += n
                file_len -= n
            else:
                fuzzed_data[addr] = _mutate_byte(fuzzed_data[addr], fuzz_type, special=self.special)
                bytes_fuzzed += 1
        if fix_ext is not None:
            fuzzed_data = file_fixer.auto_fixer(fuzzed_data, fix_ext)
        return bytes_fuzzed, fuzzed_data

