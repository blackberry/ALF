################################################################################
# Name   : Some fixups
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
import struct
import zlib

_KNOWN_EXTS = {}


def _coerce_ascii(c):
    """
    coerce an ASCII value into the alphabetical range
    """
    while True:
        if c > 127: c -= 128
        if c < 64:  c += 64
        if (c >= 65 and c <= 90) or (c >= 97 and c <= 122):
            return c
        c += 7 # just fudge it until it falls into the ascii range


def fix_png(data):
    """
    Fix the signature and checksums on a fuzzed PNG image.
    """
    out = [b"\x89PNG\r\n\x1A\n"]
    data = bytes(data[8:])
    chunk = 0
    while len(data) >= 8:
        chunklen = data[:4]
        out.append(chunklen)
        chunklen = struct.unpack("!I", chunklen)[0]
        if chunk == 0:
            chunkname = b"IHDR" # make sure the first tag is correct
        else:
            chunkname = data[4:8]
            #chunkname = bytes(_coerce_ascii(c) for c in data[4:8])
        out.append(chunkname)
        data = data[8:]
        if len(data) < chunklen:
            break
        else:
            chunkdata = data[:chunklen]
            chunkcrc = zlib.crc32(chunkname) & 0xFFFFFFFF
            chunkcrc = zlib.crc32(chunkdata, chunkcrc) & 0xFFFFFFFF
            out.append(chunkdata)
            out.append(struct.pack("!I", chunkcrc))
            data = data[chunklen+4:] # skip the old crc
        chunk += 1
    out.append(data)
    return b"".join(out)
_KNOWN_EXTS["png"] = fix_png


def auto_fixer(data, ext):
    """
    Attempt to automatically fix fuzzed data based on the file extension.
    If *ext* represents a known extension, it will be passed to the appropriate
    function to fix it's signature and/or checksums. If *ext* is not know, data
    is returned unmodified.
    """
    try:
        fixer = _KNOWN_EXTS[ext.lower().lstrip('.')]
    except KeyError:
        return data
    return fixer(data)

