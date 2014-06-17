********************************************
:mod:`alf.fuzz` ALF Fuzzing Library
********************************************

.. py:module:: alf.fuzz
    :synopsis: Library of template mutation functions

This module provides a set of mutation functions useful for fuzzer development.

Functions
=========

.. autofunction:: alf.fuzz.auto_fixer

.. autofunction:: alf.fuzz.find_xmlattrs

.. autofunction:: alf.fuzz.fix_png

.. autofunction:: alf.fuzz.fuzz_xmlattrs

.. autofunction:: alf.fuzz.random_binfuzz_type

.. autofunction:: alf.fuzz.random_intfuzz_type

.. autofunction:: alf.fuzz.random_strfuzz_type

Classes
=======

.. autoclass:: alf.fuzz.BinaryFileFuzzer
   :members:

.. autoclass:: alf.fuzz.FuzzableInteger
   :members:

.. autoclass:: alf.fuzz.IntegerFuzzer
   :members:

.. autoclass:: alf.fuzz.StringFuzzer
   :members:

.. autoclass:: alf.fuzz.Grammar
   :members:

Constants
=========

.. data:: alf.fuzz.BINFUZZ_ALTERNATE

   randomly selected value from set:
   0xAA, 0x55, 0x0A, 0x05, 0xA0, 0x50, 0x0F, 0xF0

.. data:: alf.fuzz.BINFUZZ_BOUNDARY

   byte = (2^x + y) & 0xFF

   x is a randomly selected whole number beginning at 0 up to and including 7
   y is randomly selcted from set: -2, -1, 0

.. data:: alf.fuzz.BINFUZZ_CHOP

   remove a chunk of data (ie. [1,2,3,4,5] -> [1,4,5])
   the max chunk size is 64 bytes

.. data:: alf.fuzz.BINFUZZ_CORRUPT

   insert a chunk of bytes with random values

.. data:: alf.fuzz.BINFUZZ_CORRUPT_INPLACE

   replace a chunk of bytes with random values

.. data:: alf.fuzz.BINFUZZ_DEC

   decrement byte

.. data:: alf.fuzz.BINFUZZ_DUP

   duplicate a chunk of bytes (ie. [1,2,3,4,5] -> [1,2,3,2,3,4,5])

.. data:: alf.fuzz.BINFUZZ_INC

   increment byte

.. data:: alf.fuzz.BINFUZZ_MAX

   255

.. data:: alf.fuzz.BINFUZZ_NEGATE

   flip all bits in the byte

.. data:: alf.fuzz.BINFUZZ_ONE

   1

.. data:: alf.fuzz.BINFUZZ_RANDOM

   random value

.. data:: alf.fuzz.BINFUZZ_SPECIAL

   special value, user defined

.. data:: alf.fuzz.BINFUZZ_SWAP

   swap two chunks

.. data:: alf.fuzz.BINFUZZ_XOR

   byte XOR with a randomly selected pattern

   the patterns set includes:
   0x11, 0x22, 0x33, 0x44, 0x55, 0x88, 0x99, 0xAA, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xFF

.. data:: alf.fuzz.BINFUZZ_ZERO

   0

.. data:: alf.fuzz.BINFUZZ_N

   The total number of ``INTFUZZ_*`` constants defined.

.. data:: alf.fuzz.SPECIAL_BINFUZZ_VALUE

   The default special value selected by :data:`~BINFUZZ_SPECIAL`. ascii char ``'A'``

.. data:: alf.fuzz.INTFUZZ_ALTERNATE

   value is randomly selected from set:
   0xAAAAAAAA, 0x55555555, 0xAAAA0000, 0x55550000,
   0x0000AAAA, 0x00005555, 0xFFFF0000, 0xFF00FF00,
   0x00FF00FF, 0x00FFFF00, 0xF0F0F0F0, 0x0F0F0F0F,
   0xFF0000FF, 0xF000000F

.. data:: alf.fuzz.INTFUZZ_BOUNDARY

   2^x + y

   x is a randomly selected whole number beginning at 0 up to and including 31
   y is randomly selected from set: -2, -1, 0

.. data:: alf.fuzz.INTFUZZ_DEC

   decrement

.. data:: alf.fuzz.INTFUZZ_FLOAT

   float

.. data:: alf.fuzz.INTFUZZ_INC

   increment

.. data:: alf.fuzz.INTFUZZ_MAX

   max int

.. data:: alf.fuzz.INTFUZZ_MIN

   min int

.. data:: alf.fuzz.INTFUZZ_ONE

   1

.. data:: alf.fuzz.INTFUZZ_RANDOM

   random value

.. data:: alf.fuzz.INTFUZZ_SPECIAL

   special value, user defined

.. data:: alf.fuzz.INTFUZZ_STRING

   stringify, and mutate using :class:`~StringFuzzer`

.. data:: alf.fuzz.INTFUZZ_ZERO

   0

.. data:: alf.fuzz.INTFUZZ_N

   The total number of ``INTFUZZ_*`` constants defined.

.. data:: alf.fuzz.SPECIAL_INTFUZZ_VALUE

   The default special value selected by :data:`~INTFUZZ_SPECIAL`. 0x12345678

.. data:: alf.fuzz.STRFUZZ_CORRUPT

   Mutate string with random bytes (0-255), maintaining length.

.. data:: alf.fuzz.STRFUZZ_DELIMITERS

   replace a chunk of bytes with a random delimiter.

.. data:: alf.fuzz.STRFUZZ_EMPTY

   Return an empty string.

.. data:: alf.fuzz.STRFUZZ_FORMAT_CHAR

   Return ``%n`` repeated between 1 and 32 times.

.. data:: alf.fuzz.STRFUZZ_GROW

   Add two spaces to the end of the string.

.. data:: alf.fuzz.STRFUZZ_INT

   Replace the string with the string representation of a random decimal integer.

.. data:: alf.fuzz.STRFUZZ_NULL

   Overwrite a random position in the string with a nul character (``\0``).

.. data:: alf.fuzz.STRFUZZ_PREV_DIRS

   Return ``../`` repeated between 1 and 32 times.

.. data:: alf.fuzz.STRFUZZ_RANDLEN

   Append 'a' to the string, up to a random length.

.. data:: alf.fuzz.STRFUZZ_SHRINK

   Cut the last byte off the string.

.. data:: alf.fuzz.STRFUZZ_SPECIAL

   Replace the string with the special value defined when :class:`~StringFuzzer` was instantiated.

.. data:: alf.fuzz.STRFUZZ_XSS

   Return one of several XSS strings.

.. data:: alf.fuzz.STRFUZZ_N

   The total number of ``STRFUZZ_*`` constants defined.

.. data:: alf.fuzz.SPECIAL_STRFUZZ_VALUE

   The default special value selected by :data:`~STRFUZZ_SPECIAL`. ascii char ``'A'*1024``

.. data:: alf.fuzz.STRFUZZ_XSS_VALUES

   The set of XSS strings selected from by :data:`~STRFUZZ_XSS`.

