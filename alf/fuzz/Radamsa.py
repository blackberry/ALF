################################################################################
# Name   : Radamsa.py
# Author : Tyson Smith
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
import stat
import subprocess
import sys
import tempfile

################################################################################
# Globals
################################################################################

TOOL_DIR = os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "..", "lib", "Radamsa")

################################################################################
# Classes
################################################################################

class RadamsaFuzzer(object):
    """
    This class is a wrapper around Radamsa
    (https://code.google.com/p/ouspg/wiki/Radamsa).

    Radamsa is a general purpose fuzzer.  It is intended to be used for
    breaking valid sample files in ways that might expose errors in
    programs processing them.  For more information read the fine
    manual page or visit http://code.google.com/p/ouspg/
    Radamsa was written by Aki Helin at OUSPG.
    """
    def __init__(self):
        if sys.platform.startswith("linux"):
            self.bin = os.path.join(TOOL_DIR, "radamsa-linux")
            if os.path.isfile(self.bin):
                os.chmod(self.bin, os.stat(self.bin).st_mode | stat.S_IXUSR)
            else:
                raise RuntimeError("Missing file %s" % self.bin)
        elif sys.platform.startswith("win32"):
            self.bin = os.path.join(TOOL_DIR, "radamsa-windows.exe")
            if not os.path.isfile(self.bin):
                raise RuntimeError("Missing file %s" % self.bin)
        else:
            raise RuntimeError("RadamsaFuzzer not supported on this platform")
        self.sys_rnd = random.SystemRandom()

    def fuzz_data(self, in_data):
        """
        This method mutates the given input data using Radamsa.

        :meth:`~fuzz_data` returns a string containing mutated data.
        """
        cmd = [self.bin, "-s", str(self.sys_rnd.randint(0, 0xFFFFFFFF))]
        with tempfile.TemporaryFile() as f_in:
            f_in.write(in_data)
            f_in.seek(0)
            with tempfile.TemporaryFile() as f_out:
                subprocess.Popen(cmd, shell=False, stdin=f_in, stdout=f_out, stderr=f_out).wait()
                f_out.seek(0)
                return f_out.read()

    def fuzz_file(self, in_file, out_file):
        """
        This method reads and mutates the data in in_file using Radamsa. 
        The mutated data is then writtem to out_file.
        """
        cmd = [self.bin, "-s", str(self.sys_rnd.randint(0, 0xFFFFFFFF)), "-o", out_file, in_file]
        with open(os.devnull, "w") as nul:
            subprocess.Popen(cmd, shell=False, stdout=nul, stderr=nul).wait()

import unittest

class RadamsaTests(unittest.TestCase):

    def test_fuzz_file(self):
        f = RadamsaFuzzer()
        f_d, f_n = tempfile.mkstemp()
        test_case = "Fuzztron 2000 ALF <test> (12x123x1234)"
        with os.fdopen(f_d, "wb") as fp:
            fp.write(test_case)
        for _ in range(10):
            f.fuzz_file(f_n, "tmp_fuzz_radamsa")
            with open("tmp_fuzz_radamsa", "rb") as fp:
                self.assertNotEqual(fp.read(), test_case)
        os.remove(f_n)
        os.remove("tmp_fuzz_radamsa")

    def test_fuzz_data(self):
        f = RadamsaFuzzer()
        test_case = "Fuzztron 2000 ALF <test> (12x123x1234)"
        for _ in range(10):
            self.assertNotEqual(f.fuzz_data(test_case), test_case)

suite = unittest.TestLoader().loadTestsFromTestCase(RadamsaTests)
