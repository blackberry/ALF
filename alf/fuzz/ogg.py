################################################################################
# Name   : Ogg fuzzer
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
#
# TODO: hangs sometimes
# TODO: vorbis audio packets (non-headers) should all start with a 0 bit (0x80 clear)
#
import struct

CRC_LUT = []

def ogg_crc32(data):
    if not CRC_LUT:
        # init CRC lookup table
        for idx in range(256):
            r = idx << 24
            for i in range(8):
                if r & 0x80000000:
                    r = (r << 1) ^ 0x04C11DB7
                else:
                    r <<= 1
            CRC_LUT.append(r & 0xFFFFFFFF)
    reg = 0
    for i in bytes(data):
        reg = ((reg << 8) ^ CRC_LUT[((reg >> 24) & 0xFF) ^ i]) & 0xFFFFFFFF
    return reg

class OggPage(object):
    def __init__(self):
        self.header = None
        self.data = []
        self.special = None

    def identify(self):
        for i in self.data:
            if i[1:7] == b"vorbis":
                self.special = i[:7]
                return

    def fuzz_header(self, fuzzer):
        #print "hdr",
        out = bytes(fuzzer(self.header[4:])[:18])
        return b"".join([b"OggS", out, b"\x00" * (22 - len(out))])

    def fuzz(self, fuzzer):
        """Return a fuzzed version of this page."""
        # TODO, for these vorbis header pages, should fuzz the parameters within structures
        # https://www.xiph.org/vorbis/doc/Vorbis_I_spec.html#x1-600004.2
        #print "fuzz",
        if self.special == b"\x01vorbis":
            #print "spc1",
            hdr = self.fuzz_header(fuzzer)
            vorbhdr = bytes(fuzzer(self.data[0][7:])[:22])
            data = [b"".join([b"\x01vorbis", vorbhdr, b"\x01" * (23 - len(vorbhdr))])]
        elif self.special: # unknown "special" page
            #print "spcx (k)"
            return b"".join([self.header] + self.data)
        else:
            #print "nspc",
            hdr = self.fuzz_header(fuzzer)
            data = [bytes(fuzzer(i)[:255]) for i in self.data[:255]]
        out = b"".join([hdr, bytes([len(data)])] + [bytes([len(i)]) for i in data] + data)
        pagecrc = ogg_crc32(out)
        out = b"".join([out[:22], struct.pack("<I", pagecrc), out[26:]])
        #print "ok"
        return out

class Ogg(object):
    def __init__(self):
        self.pages = []

    @classmethod
    def from_data(cls, data):
        res = cls()
        while data:
            nsegs = data[26]
            page = OggPage()
            page.header, data = data[:27+nsegs], data[27:]
            ptr = nsegs
            for i in range(nsegs):
                nptr = ptr+data[i]
                page.data.append(data[ptr:nptr])
                ptr = nptr
            data = data[ptr:]
            page.identify()
            res.pages.append(page)
        return res

    def fuzz(self, fuzzer):
        #print "ogg_fuzz>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
        out = b"".join(p.fuzz(fuzzer) for p in self.pages)
        #print "ogg_fuzz<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<"
        return out


if __name__ == "__main__":
    import argparse
    import random
    ap = argparse.ArgumentParser("ogg fuzz test")
    ap.add_argument("infile", type=argparse.FileType("rb"), help="input file")
    ap.add_argument("outfile", type=argparse.FileType("wb"), help="output file")
    ap.add_argument("--aggression", "-g", type=float, help="bit flip probability (0-1)", default=0.0)
    args = ap.parse_args()
    if not (0.0 <= args.aggression <= 1.0):
        ap.error("Invalid aggression value")
    random.seed()
    if args.aggression == 0.0:
        fuzz = lambda x:x
    else:
        def fuzz(v):
            o = bytearray()
            for b in v:
                if args.aggression == 1.0 or random.random() < args.aggression:
                    o.append(b ^ random.randint(0, 255))
                else:
                    o.append(b)
            return bytes(o)
    args.outfile.write(Ogg.from_data(args.infile.read()).fuzz(fuzz))

