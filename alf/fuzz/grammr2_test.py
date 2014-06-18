################################################################################
# Description: Grammr2 tests
# Author: Jesse Schwartzentruber
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
from .grammr2 import Grammar, WeightedChoice
from .grammr2_crack import GrammarCracker
import re
import unittest

class GrammarTests(unittest.TestCase):

    def test_broken(self):
        w = Grammar("root 'a' 'b'\\\n"
                    "     'c'\n")
        self.assertEqual(w.generate(), "abc")

    def test_wchoice(self):
        iters = 10000
        w = WeightedChoice([(1, 1), (2, 1), (3, 1)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        for v in r.values():
            self.assertAlmostEqual(v/iters, 1/3, delta=.02)
        w = WeightedChoice([(1, 1), (2, 2), (3, 1)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(r[1]/iters, 0.25, delta=.02)
        self.assertAlmostEqual(r[2]/iters, 0.5, delta=.02)
        self.assertAlmostEqual(r[3]/iters, 0.25, delta=.02)
        w = WeightedChoice([(1, 3), (2, 1), (3, 1)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(r[1]/iters, 0.6, delta=.02)
        self.assertAlmostEqual(r[2]/iters, 0.2, delta=.02)
        self.assertAlmostEqual(r[3]/iters, 0.2, delta=.02)
        w = WeightedChoice([(1, 1), (2, 1), (3, 4)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(r[1]/iters, 1/6, delta=.02)
        self.assertAlmostEqual(r[2]/iters, 1/6, delta=.02)
        self.assertAlmostEqual(r[3]/iters, 2/3, delta=.02)

    def test_funcs(self):
        iters = 10
        gram = "root    {1,10}  func\n" \
               "func    |       'z' zero(nuvar) '\\n'\n" \
               "        |       'a' alpha(alvar , '*,' rep) '\\n'\n" \
               "        |       nuvar '\\n'\n" \
               "        |       alvar '\\n'\n" \
               "nuvar           'n' /[0-9]{6}/\n" \
               "alvar           'c' /[a-z]{6}/\n" \
               "rep             /[0-9]/"
        def zero(inp):
            return inp.replace("0", "z")
        def alpha(inp, rep):
            return "%s/%s" % (rep, inp.replace("a", rep))
        w = Grammar(gram, zero=zero, alpha=alpha)
        i = 0
        while i < iters:
            i += 1
            for line in w.generate().splitlines():
                if line.startswith("zn"):
                    self.assertRegex(line[2:], r"^[1-9z]{6}$")
                elif line.startswith("a"):
                    self.assertRegex(line[1:], r"^(\*,[0-9])/c(\1|[b-z]){6}$")
                elif line.startswith("n"):
                    self.assertRegex(line[1:], r"^[0-9]{6}$")
                elif line.startswith("c"):
                    self.assertRegex(line[1:], r"^[a-z]{6}$")
                else:
                    raise Exception("unexpected line: %s" % line)

    def test_plus(self):
        iters = 10000
        gram = "var     | 'a'\n" \
               "        | 'b'\n" \
               "        | 'c'\n" \
               "root    | var\n" \
               "        | 'd'"
        w = Grammar(gram)
        r = {'a':0, 'b':0, 'c':0, 'd':0}
        i = 0
        while i < iters:
            i += 1
            v = w.generate()
            r[v] += 1
        #for v in "abc":
        #    self.assertAlmostEqual(r[v]/iters, 1/6, delta=0.03)
        #self.assertAlmostEqual(r['d']/iters, 0.5, delta=0.03)
        for v in r.values():
            self.assertAlmostEqual(1.0*v/iters, 0.25, delta=0.03)

    def test_basic(self):
        w = Grammar("root    ok\n"
                    "ok      '1'")
        self.assertEqual(w.generate(), "1")
        w = Grammar("root   a\n"
                    "a      '1234' /[a-z]/ b\n"
                    "b      | c\n"
                    "       | d\n"
                    "c      'C'\n"
                    "d      'D'")
        r = {"C": 0, "D": 0}
        for _ in range(1000):
            v = w.generate()
            self.assertRegex(v, r"^1234[a-z][CD]$")
            r[v[-1]] += 1
        self.assertAlmostEqual(r["C"], 500, delta=50)
        self.assertAlmostEqual(r["D"], 500, delta=50)

    def test_quo1(self):
        w = Grammar("root    '\\\\'")
        g = w.generate()
        self.assertEqual(g, "\\")
        w = Grammar("root    \"\\\\\"")
        g = w.generate()
        self.assertEqual(g, "\\")

    def test_quo2(self):
        w = Grammar("root    '\\''")
        g = w.generate()
        self.assertEqual(g, "'")
        w = Grammar("root    \"\\\"\"")
        g = w.generate()
        self.assertEqual(g, "\"")

    def test_quo3(self):
        w = Grammar("root    '\\'some'")
        g = w.generate()
        self.assertEqual(g, "'some")
        w = Grammar("root    \"\\\"some\"")
        g = w.generate()
        self.assertEqual(g, "\"some")

    def test_quo4(self):
        w = Grammar("root    'some\\''")
        g = w.generate()
        self.assertEqual(g, "some'")
        w = Grammar("root    \"some\\\"\"")
        g = w.generate()
        self.assertEqual(g, "some\"")

    def test_quo5(self):
        # unbalanced parens, end paren is escaped .. should raise
        with self.assertRaises(Exception):
            Grammar(r"root    '\\\\\\\'")
        with self.assertRaises(Exception):
            Grammar(r'root    "\\\\\\\"')

    def test_quo6(self):
        w = Grammar(r"root    '\\\\\\\'\\'")
        g = w.generate()
        self.assertEqual(g, "\\\\\\'\\")
        w = Grammar(r'root    "\\\\\\\"\\"')
        g = w.generate()
        self.assertEqual(g, "\\\\\\\"\\")

    def test_quo7(self):
        w = Grammar("root    \"'some\"")
        g = w.generate()
        self.assertEqual(g, "'some")
        w = Grammar("root    '\"some'")
        g = w.generate()
        self.assertEqual(g, "\"some")

    def test_quo8(self):
        w = Grammar("root    \"'\"")
        g = w.generate()
        self.assertEqual(g, "'")
        w = Grammar("root    \"''\"")
        g = w.generate()
        self.assertEqual(g, "''")
        w = Grammar("root    \"'''\"")
        g = w.generate()
        self.assertEqual(g, "'''")
        w = Grammar("root    '\"'")
        g = w.generate()
        self.assertEqual(g, "\"")
        w = Grammar("root    '\"\"'")
        g = w.generate()
        self.assertEqual(g, "\"\"")
        w = Grammar("root    '\"\"\"'")
        g = w.generate()
        self.assertEqual(g, "\"\"\"")

    def test_quo9(self):
        #right: "<h5 id='id824837' onload='chat(\'id705147\',1,\' width=\\\'2pt\\\'\')'>"
        #                                                        ^  -- esc() --   ^
        #wrong: "<h5 id='id824837' onload='chat(\'id705147\',1,\\\' width=\\\'2pt\'\')'>"
        #                                                      ^  -- esc() --   ^
        w = Grammar("root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\"\n"
                    "id     'id' /[0-9]{6}/\n"
                    "func   \"chat('\" id \"',\" /[0-9]/ \",'\" esc(\" width='2pt'\") \"')\"\n"
                    , esc=lambda x: re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(w.generate(), r"^<h5 id='id[0-9]{6}' onload='chat\(\\'id[0-9]{6}"
                                       r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")
        # same grammar with '@id' in chat() instead of 'id'
        w = Grammar("root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\"\n"
                    "id     'id' /[0-9]{6}/\n"
                    "func   \"chat('\" @id \"',\" /[0-9]/ \",'\" esc(\" width='2pt'\") \"')\"\n"
                    , esc=lambda x: re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(w.generate(), r"^<h5 id='(id[0-9]{6})' onload='chat\(\\'\1"
                                       r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")

    def test_func_nest_tracked(self):
        w = Grammar("root   id a(b(@id))\n"
                    "id     'i'\n"
                    , a=lambda x: "a" + x, b=lambda x: "b" + x)
        self.assertEqual(w.generate(), "iabi")

    def test_tracked1(self):
        w = Grammar("root    id '\\n' esc(\"'\" @id \"'\")\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x: re.sub(r"'", "\\'", x))
        defn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "\\'%s\\'" % defn)

    def test_tracked2(self):
        w = Grammar("root    id '\\n' esc('not', @id)\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x, y: x)
        defn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "not")

    def test_tracked3(self):
        w = Grammar("root    esc(id) '\\n' @id\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x: "%s\n%s" % (x, "".join("%02x" % ord(c) for c in x)))
        defn, hexn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual("".join("%02x" % ord(c) for c in defn), hexn)
        self.assertEqual(defn, use)

    def test_tracked4(self):
        w = Grammar("root    @id\n"
                    "id      'id' /[0-9]/")
        self.assertEqual(w.generate(), "")

    def test_tracked5(self):
        w = Grammar("root    esc(id) @id\n"
                    "id      'id' /[0-9]/",
                    esc=lambda x: "")
        self.assertRegex(w.generate(), r"^id[0-9]$")

    def test_tyson(self):
        w = Grammar('root   /[0-1]{1}/ "]"')
        o = w.generate()
        self.assertIn(o, ["0]", "1]"])

    def test_re(self):
        w = Grammar('root /.*/')
        r = GrammarCracker(w)
        for _ in range(100):
            r.crack(w.generate())

    def test_crack(self):
        w = Grammar('root   "a" b c\n'
                    'b  0   ""\n'
                    '   1   "1"\n'
                    '   1   "2"\n'
                    '   1   "3"\n'
                    '   1   "4"\n'
                    'c{0,2} "c"')
        GrammarCracker(w).crack(w.generate())

    def test_crack2(self):
        w = Grammar('root   b\n'
                    'b{7}  c\n'
                    'c  1   "1"\n'
                    '   1   "2"\n'
                    '   1   "3"\n'
                    '   4   "4"')
        r = GrammarCracker(w)
        for _ in range(10):
            g = w.generate()
            nw = r.crack(g)
            ref = {}
            for c in g:
                try:
                    ref[c] += 1
                except KeyError:
                    ref[c] = 1
            stats = {}
            for _ in range(100):
                for c in nw.generate():
                    try:
                        stats[c] += 1
                    except KeyError:
                        stats[c] = 1
            for c, v in stats.items():
                self.assertAlmostEqual(v / 100, ref[c], 0)

    def test_bin(self):
        w = Grammar("root x'68656c6c6f2c20776f726c6400'")
        self.assertEqual(w.generate(), b"hello, world\0")


suite = unittest.TestLoader().loadTestsFromTestCase(GrammarTests)

