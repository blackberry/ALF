################################################################################
# Name   : ValueFuzz.py
# Author : Jesse Schwartzentruber
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
from copy   import copy
import os
from random import randint, choice as randchoice
from sys    import maxsize as MAXINT

################################################################################
# Globals
################################################################################

STRFUZZ_EMPTY           = 0
STRFUZZ_CORRUPT         = 1 # random bytes matching length of original value
STRFUZZ_NULL            = 2 # \0 byte in random position
STRFUZZ_INT             = 3 # random decimal integer
STRFUZZ_SHRINK          = 4 # cut last byte off of string
STRFUZZ_GROW            = 5 # add 2 'a's to end of string
STRFUZZ_SPECIAL         = 6 # special value, user defined
STRFUZZ_JUNK            = 7 # random bytes random length
STRFUZZ_XSS             = 8 # add random XSS string
STRFUZZ_PREV_DIRS       = 9 # add "../" a few times
STRFUZZ_FORMAT_CHAR     = 10 # add "%n" a few times
STRFUZZ_DELIMITERS      = 11 # common delimiters
# add new STRFUZZ types above, and update count below
STRFUZZ_N               = 12

SPECIAL_STRFUZZ_VALUE   = 'A' * 1024

## Special array of XSS strings for fuzzing
STRFUZZ_XSS_VALUES = ["\"><script>document.location='http://localhost:9999/';</script>",
                      "<script src=http://localhost:9999/></script>",
                      "<iframe http://localhost:9999/>",
                      "<link rel=\"stylesheet\" href=\"http://localhost:9999/\">"]

INTFUZZ_RANDOM     = 0 # random value
INTFUZZ_INC        = 1 # increment
INTFUZZ_DEC        = 2 # decrement
INTFUZZ_MAX        = 3 # max int
INTFUZZ_ZERO       = 4 # 0
INTFUZZ_ONE        = 5 # 1
INTFUZZ_STRING     = 6 # mutate as string
INTFUZZ_FLOAT      = 7 # float
INTFUZZ_SPECIAL    = 8 # special value, user defined
INTFUZZ_MIN        = 9 # min int
INTFUZZ_BOUNDARY   = 10 # 2^x + (-2, -1 or 0)
INTFUZZ_ALTERNATE  = 11 # 1010101... or 0101010...
# add new INTFUZZ types above, and update count below
INTFUZZ_N          = 12

SPECIAL_INTFUZZ_VALUE = 0x12345678

################################################################################
# Functions
################################################################################

def random_strfuzz_type():
    """
    This function will return a randomly chosen fuzz_type from ``STRFUZZ_*``.
    """
    return randint(0, STRFUZZ_N-1)

def random_intfuzz_type():
    """
    This function will return a randomly chosen fuzz_type from ``INTFUZZ_*``.
    """
    return randint(0, INTFUZZ_N-1)

################################################################################
# Classes
################################################################################

class StringFuzzer(object):
    """
    This class is designed to mutate a string. *fuzz_type* can be one
    of the ``STRFUZZ_*`` constants, or ``None`` to select at random for each mutation.
    *special* will override the default value of ``'A'*1024`` used when :data:`STRFUZZ_SPECIAL` is
    selected. When *fuzz_type* is None, specific fuzz types can be disabled using
    :meth:`~disable_fuzz_type`. *max_length* will limit the size of the string returned.
    The default for max_length is 10KB.
    """
    def __init__(self, fuzz_type=None, special=None, max_length=10*1024):
        if fuzz_type is None:
            self.fuzz_types = list(range(STRFUZZ_N))
        else:
            self._validate_fuzz_type(fuzz_type)
            self.fuzz_types = [fuzz_type]
        if special is None:
            special = SPECIAL_STRFUZZ_VALUE
        if not isinstance(special, str):
            raise TypeError("special must be of type str not %s" % special.__class__.__name__)
        self.special = special
        if not isinstance(max_length, int):
            raise TypeError("max_length must be of type int not %s" % max_length.__class__.__name__)
        if max_length <= 0:
            raise ValueError("max_length must be greater than zero")
        self.max_len = max_length

    @staticmethod
    def _validate_fuzz_type(fuzz_type):
        if not (fuzz_type == int(fuzz_type) and 0 <= fuzz_type < STRFUZZ_N):
            raise ValueError("Unknown StringFuzzer fuzz type: %r" % str(fuzz_type))

    def disable_fuzz_type(self, fuzz_type):
        """
        This method disables the given *fuzz_type* for all future mutations.
        """
        del self.fuzz_types[self.fuzz_types.index(fuzz_type)]

    def set_special_value(self, special):
        """
        This method will set a new special value to be used by :data:`STRFUZZ_SPECIAL`.
        """
        self.special = special

    def random_fuzz_type(self):
        """
        This function will return a randomly chosen fuzz type from ``STRFUZZ_*``.
        Any fuzz types disabled by :meth:`~disable_fuzz_type` will be excluded.
        """
        return randchoice(self.fuzz_types)

    def fuzz_value(self, value, fuzz_type=None):
        """
        This method mutates a given string value. The input string is *value*, which
        may or may not affect the mutation. *fuzz_type* specifies how the string will
        be mutated. A value of None indicates that a random fuzz_type should be used
        for each mutation of the string.

        The result is a mutation which may or may not be based on the original string.
        """
        if fuzz_type is None:
            fuzz_type = self.random_fuzz_type()
        else:
            self._validate_fuzz_type(fuzz_type)

        if fuzz_type == STRFUZZ_EMPTY:
            result = ""
        elif fuzz_type == STRFUZZ_CORRUPT:
            result = os.urandom(len(value))
        elif fuzz_type == STRFUZZ_NULL:
            if len(value):
                out = list(value)
                out[randint(0, len(value)-1)] = chr(0)
                result = "".join(out)
            else:
                result = value
        elif fuzz_type == STRFUZZ_INT:
            result = IntegerFuzzer().fuzz_value(FuzzableInteger("0"))
        elif fuzz_type == STRFUZZ_SHRINK:
            result = value[:-1]
        elif fuzz_type == STRFUZZ_GROW:
            result = "%saa" % value
        elif fuzz_type == STRFUZZ_JUNK:
            result = os.urandom(randint(1, self.max_len))
        elif fuzz_type == STRFUZZ_XSS:
            result = randchoice(STRFUZZ_XSS_VALUES)
        elif fuzz_type == STRFUZZ_SPECIAL:
            result = self.special
        elif fuzz_type == STRFUZZ_PREV_DIRS:
            result = "../" * randint(1, 32)
        elif fuzz_type == STRFUZZ_FORMAT_CHAR:
            result = randchoice(["%n", "%s"]) * randint(1, 32)
        elif fuzz_type == STRFUZZ_DELIMITERS:
            result = randchoice([" ", ",", ".", ";", ":", "\n", "\t"])
        else:
            raise ValueError("Unhandled Fuzz Type: %d" % fuzz_type)
        return result

class FuzzableInteger(object):
    """
    This class represents a fuzzable integer value, with some extra
    formatting information preserved. The input value is given as a string.
    If the string begins with ``0x``, the value is assumed to be hexadecimal
    with a prefix, and will be output as such unless changed by IntegerFuzzer.
    If *is_hex* is True, the value is also treated as hexadecimal, but will
    not be output with the ``0x`` prefix. If *maintain_width* is set, the printed
    width of the integer will be maintained on output.
    """
    def __init__(self, value_as_string, is_hex=False, maintain_width=False):
        self.has_prefix = value_as_string.startswith("0x")
        if self.has_prefix:
            self.value = int(value_as_string[2:], 16)
            is_hex = True
        elif is_hex:
            self.value = int(value_as_string, 16)
        else:
            try:
                self.value = int(value_as_string, 10)
            except ValueError:
                self.value = int(value_as_string, 16)
                is_hex = True
        if maintain_width:
            self.width = len(value_as_string)
            if is_hex:
                if self.has_prefix:
                    self.width -= 2
                self.maxint = 16**self.width-1
            else:
                self.maxint = 10**self.width-1
            self.width = -self.width
            self.widths = "0" * self.width
        else:
            self.width = None
            self.maxint = MAXINT
            self.widths = ""
        self.is_hex = is_hex

    def __str__(self):
        if self.is_hex:
            res = ("%s%x" % (self.widths, self.value & 0xFFFFFFFF))[self.width:]
            if self.has_prefix:
                return "0x%s" % res
            return res
        else:
            return ("%s%d" % (self.widths, self.value & 0xFFFFFFFF))[self.width:]

class IntegerFuzzer(object):
    """
    This class is designed to mutate an integer. *fuzz_type* can be one
    of the ``INTFUZZ_*`` constants, or ``None`` to select at random for each mutation.
    *special* will override the default value of 0x12345678 used when :data:`INTFUZZ_SPECIAL` is
    selected. When *fuzz_type* is None, specific fuzz types can be disabled using
    :meth:`~disable_fuzz_type`.
    """
    def __init__(self, fuzz_type=None, special=None):
        if fuzz_type is None:
            self.fuzz_types = list(range(INTFUZZ_N))
        else:
            self._validate_fuzz_type(fuzz_type)
            self.fuzz_types = [fuzz_type]
        if special is None:
            special = SPECIAL_INTFUZZ_VALUE
        if not isinstance(special, int):
            raise TypeError("special must be of type int not %s" % special.__class__.__name__)
        self.special = special

    @staticmethod
    def _validate_fuzz_type(fuzz_type):
        if not (fuzz_type == int(fuzz_type) and 0 <= fuzz_type < INTFUZZ_N):
            raise ValueError("Unknown IntegerFuzzer fuzz type: %r" % str(fuzz_type))

    def disable_fuzz_type(self, fuzz_type):
        """
        This method disables the given *fuzz_type* for all future mutations.
        """
        del self.fuzz_types[self.fuzz_types.index(fuzz_type)]

    def set_special_value(self, special):
        """
        This method will set a new special value to be used by :data:`INTFUZZ_SPECIAL`.
        """
        self.special = special

    def random_fuzz_type(self):
        """
        This function will return a randomly chosen fuzz type from ``INTFUZZ_*``.
        Any fuzz types disabled by :meth:`~disable_fuzz_type` will be excluded.
        """
        return randchoice(self.fuzz_types)

    def fuzz_value(self, fuzzable_integer, fuzz_type=None):
        """
        This method mutates a given integer value, wrapped in a :class:`FuzzableInteger`
        instance. The input value may not affect the mutation, depending on the fuzz
        type selected. *fuzz_type* specifies how the integer will
        be mutated. A value of None indicates that a random fuzz_type should be used
        for each mutation of the integer.

        The result is a stringified mutation which may or may not be based on the original
        integer value.
        """
        if fuzz_type is None:
            fuzz_type = self.random_fuzz_type()
        else:
            self._validate_fuzz_type(fuzz_type)

        result = copy(fuzzable_integer)
        if fuzz_type == INTFUZZ_RANDOM:
            result.value = randint(0, result.maxint)
        elif fuzz_type == INTFUZZ_INC:
            result.value += 1
        elif fuzz_type == INTFUZZ_DEC:
            result.value -= 1
        elif fuzz_type == INTFUZZ_MAX:
            result.value = result.maxint
        elif fuzz_type == INTFUZZ_MIN:
            result.value = -result.maxint-1
        elif fuzz_type == INTFUZZ_ZERO:
            result.value = 0
        elif fuzz_type == INTFUZZ_ONE:
            result.value = 1
        elif fuzz_type == INTFUZZ_FLOAT:
            result.is_hex = False
            out = list(str(result))
            if len(out) > 1:
                out.insert(randint(1, len(out)-1), ".")
            return "".join(out)
        elif fuzz_type == INTFUZZ_STRING:
            return StringFuzzer().fuzz_value(str(result))
        elif fuzz_type == INTFUZZ_SPECIAL:
            result.value = self.special
        elif fuzz_type == INTFUZZ_BOUNDARY:
            result.value = (2**randint(0, 31)) + randint(-2, 0)
        elif fuzz_type == INTFUZZ_ALTERNATE:
            result.value = randchoice((0xAAAAAAAA, 0x55555555,
                                       0xAAAA0000, 0x55550000,
                                       0x0000AAAA, 0x00005555,
                                       0xFFFF0000, 0xFF00FF00,
                                       0x00FF00FF, 0x00FFFF00,
                                       0xF0F0F0F0, 0x0F0F0F0F,
                                       0xFF0000FF, 0xF000000F))
        else:
            assert False, "Unhandled Fuzz Type: %d" % fuzz_type
        return str(result)

