################################################################################
# Name   : ALF fuzzing library
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
from .BinaryFuzz import BINFUZZ_RANDOM, BINFUZZ_INC, BINFUZZ_DEC, BINFUZZ_ZERO
from .BinaryFuzz import BINFUZZ_MAX, BINFUZZ_SPECIAL, BINFUZZ_ONE
from .BinaryFuzz import BINFUZZ_NEGATE, BINFUZZ_XOR
from .BinaryFuzz import BINFUZZ_SWAP, BINFUZZ_DUP, BINFUZZ_BOUNDARY, BINFUZZ_ALTERNATE
from .BinaryFuzz import BINFUZZ_CORRUPT, BINFUZZ_CORRUPT_INPLACE, BINFUZZ_CHOP, BINFUZZ_N
from .BinaryFuzz import SPECIAL_BINFUZZ_VALUE
from .BinaryFuzz import random_binfuzz_type, BinaryFileFuzzer

from .file_fixer import fix_png, auto_fixer

from .ogg import Ogg

from .Radamsa import RadamsaFuzzer

from .ValueFuzz import STRFUZZ_EMPTY, STRFUZZ_CORRUPT, STRFUZZ_DELIMITERS, STRFUZZ_NULL
from .ValueFuzz import STRFUZZ_INT, STRFUZZ_SHRINK, STRFUZZ_GROW, STRFUZZ_SPECIAL
from .ValueFuzz import STRFUZZ_JUNK, STRFUZZ_XSS, STRFUZZ_PREV_DIRS
from .ValueFuzz import STRFUZZ_FORMAT_CHAR, STRFUZZ_N
from .ValueFuzz import STRFUZZ_XSS_VALUES
from .ValueFuzz import random_strfuzz_type, StringFuzzer

from .ValueFuzz import INTFUZZ_RANDOM, INTFUZZ_INC, INTFUZZ_DEC, INTFUZZ_MAX, INTFUZZ_BOUNDARY
from .ValueFuzz import INTFUZZ_ZERO, INTFUZZ_ONE, INTFUZZ_STRING, INTFUZZ_FLOAT, INTFUZZ_ALTERNATE
from .ValueFuzz import INTFUZZ_SPECIAL, INTFUZZ_MIN, INTFUZZ_N
from .ValueFuzz import random_intfuzz_type, FuzzableInteger, IntegerFuzzer

from .XmlAttributeFuzz import find_xmlattrs, fuzz_xmlattrs

#from .grammar import Grammar, WeightedChoice
from .grammr2 import Grammar, WeightedChoice
