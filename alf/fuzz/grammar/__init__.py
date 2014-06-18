##############################################################################
# Name   : ALF grammar module
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
##############################################################################
import os
import re
import sys

def import_helper():
    from os.path import dirname
    import imp
    possible_libs = ["_alf_grammar.win32",
                     "_alf_grammar.ntoarm",
                     "_alf_grammar.ntox86",
                     "_alf_grammar.linux"]
    found_lib = False
    for i in possible_libs:
        fp = None
        try:
            fp, pathname, description = imp.find_module(i, [dirname(__file__)])
            _mod = imp.load_module("_alf_grammar", fp, pathname, description)
            found_lib = True
            break
        except ImportError:
            pass
        finally:
            if fp:
                fp.close()
    if not found_lib:
        raise ImportError("Failed to load _alf_grammar module")
    return _mod
_alf_grammar = import_helper()
del import_helper

__all__ = ["Grammar", "WeightedChoice"]

REGEX_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" \
                 "abcdefghijklmnopqrstuvwxyz" \
                 "0123456789" \
                 ",./<>?;':\"[]\\{}|=_+`~!@#$%^&*() -"

WeightedChoice = _alf_grammar.WeightedChoice

RE_SYM_PARSE = re.compile(r"""^(?P<comment>\#).*$ |
                              ^(?P<whitespace>\s*)$ |
                              ^(?P<ref>@\S+)\s+(?P<ref_width>[0-9]+)\s*(?P<ref_cmt>\#.*)?$ |
                              ^(?P<star>\S+)\s+\*(?P<count>[0-9.]+)\s+(?P<star_rest>\S.*)$ |
                              ^(?P<foreign>\S+)\s+!(?P<filename>\S+)\s*(?P<foreign_rest>.*)$ |
                              ^(?P<choice>\S+)\s+(?P<choice_weight>\+|[0-9.]+)\s+(?P<choice_rest>\S.*)$ |
                              ^(?P<concat>\S+)\s+(?P<concat_rest>\S.*)$ |
                              ^(?P<not_name>\S).*$ |
                              ^\s+(?P<ccs_weight>\+|[0-9.]+)\s+(?P<ccs_rest>\S.*)$""", re.VERBOSE)
RE_CFG = re.compile(r"#\s*cfg:(.*)$")
RE_REGEX = re.compile(r"(?P<outer>\[(?P<class>[^\]]+?)\]|\.)" \
                      r"(?P<mod>\*|\+|{[0-9]+}|{[0-9]+,[0-9]+})?")
RE_REGEX_RANGE = re.compile(r".-.")
RE_QUOTE = {"\"": re.compile(r'("|\\.)'), "'": re.compile(r"('|\\.)")}

class Grammar(object):
    """Generate a language conforming to a given grammar specification.

    A Grammar consists of a set of symbol definitions which are used to define the structure of a language. The Grammar
    object is created from a text input with the format described below, and then used to generate randomly constructed
    instances of the described language. The entrypoint of the grammar is the named symbol 'root'. Lines can be
    continued if the last character on the line is a backslash character (``\\``). Comments are allowed anywhere in the
    file, preceded by a hash character (``#``). There are several special keywords which can be specified as the first
    word of a comment, which will be described later.

    Symbols can either be named or implicit. A named symbol consists of a symbol name at the beginning of a line,
    followed by at least one whitespace character, followed by the symbol definition.

        ::

            SymbolName  Definition

    Implicit symbols are defined without being assigned an explicit name. For example a regular expression can be used
    in a concatenation definition directly, without being assigned a name. Choice, star, and foreign grammar symbols
    cannot be defined implicitly.

    **Concatenation**:

            ::

                SymbolName      SubSymbol1 [SubSymbol2] ...

        A concatenation consists of one or more symbols which will be generated in succession. The sub-symbol can be
        any named symbol, reference, or an implicit declaration of allowed symbol types. A concatenation can also be
        implicitly defined as the sub-symbol of a choice or star symbol.

    **Choice**: (must be named, not implicit)

            ::

                SymbolName      Weight1     SubSymbol1
                               [Weight2     SubSymbol2]
                               [Weight3     SubSymbol3]

        A choice consists of one or more weighted sub-symbols. At generation, only one of the sub-symbols will be
        generated at random, with each sub-symbol being generated with probability of weight/sum(weights) (the sum of
        all weights in this choice). Weight can be a non-negative number, or the character ``+``. ``+`` denotes a weight
        of 1, unless the sub-symbol is another choice, in which case it will be sum of all weights in that sub-choice.
        For ``+`` to be used with a sub-choice, the sub-choice must have been previously defined in the grammar.

    **Star**: (must be named, not implicit)

            ::

                SymbolName      *Count      SubSymbol

        A star is a repetition of a sub-symbol. The number of repetitions is at most ``Count``, and at minimum 0. The
        number of repetitions generated decreases with the recursion depth of the grammar.

    **Text**:

            ::

                SymbolName      'some text'
                SymbolName      "some text"

        A text symbol is a string generated verbatim in the output. A few escape codes are recognized:
            * ``\\t``  horizontal tab (ASCII 0x09)
            * ``\\n``   line feed (ASCII 0x0A)
            * ``\\v``  vertical tab (ASCII 0x0B)
            * ``\\r``  carriage return (ASCII 0x0D)
        Any other character preceded by backslash will appear in the output without the backslash (including backslash,
        single quote, and double quote).

    **Regular expression**:

            ::

                SymbolName      [a-zA][0-9]*.+[^0-9]{2}.[^abc]{1,3}

        A regular expression (regex) symbol is a minimal regular expression implementation used for generating text
        patterns (rather than the traditional use for matching text patterns). A regex symbol consists of one or more
        parts in succession, and each part consists of a character set definition optionally followed by a repetition
        specification. The character set definition can be a period ``.`` to denote any character, a set of characters in
        brackets eg. ``[0-9a-f]``, or an inverted set of characters ``[^a-z]`` (any character except a-z). As shown, ranges can
        be used by using a dash. The dash character can be matched in a set by putting it last in the brackets. The
        optional repetition specification can be a range of integers in curly braces, eg. ``{1,10}`` will generate between
        1 and 10 repetitions (at random), a single integer in curly braces, eg. ``{10}`` will generate exactly 10
        repetitions, an asterisk character (``*``) which is equivalent to ``{0,5}``, or a plus character (``+``) which is
        equivalent to ``{1,5}``.

    **Foreign grammar**: (must be named, not implicit)

            ::

                SymbolName      !filename

        A foreign grammar. The grammar specified in the external file ``filename`` will be used to generate every
        instance of this symbol.

    **File**:

            ::

                SymbolName      &filename

        This is the same as a text symbol, except the text content comes from the external file ``filename``.

    **Random floating point decimal**:

            ::

                SymbolName      rndflt(a,b)

        A random floating-point decimal number between ``a`` and ``b`` inclusive.

    **Random integer**:

            ::

                SymbolName      rndint(a,b)

        A random integer between ``a`` and ``b`` inclusive.

    **Reference**:

            ::

                @SymbolName     MaxWidth
                SymbolRef       @SymbolName
                ScopedRef       $SymbolName

        Symbol references allow a generated symbol to be used elsewhere in the grammar. A limitation is that the
        maximum generated width must be known and declared prior to the first reference. This declaration must be at
        the beginning of the line, and must specify an integer width maximum for the symbol. There are then two ways of
        using references elsewhere in the grammar: scoped, and unscoped. An unscoped reference to ``Symbol`` is denoted
        by ``@Symbol``, and it will output a generated value of ``Symbol`` from elsewhere in the output. Unscoped
        references are fixed-width, meaning the maximum width is always occupied in the output. If the actual symbol
        value is shorter, it will be right-padded with space characters. A scoped reference obeys the scope entry/exit
        symbols and are denoted by ``$Symbol``. Scoped references are not space-padded, they will occupy the same width
        as the referenced value.

    **Scope enter/exit**:

            ::

                SymbolName      {
                SymbolName      }

        This denotes a scope. Scopes are used only for generating scoped references. They do not generate any textual
        output. Any referenced symbol generated between balanced scope enter/exit symbols will only be used as a
        scoped reference within that scope or a contained scope. Scopes don't necessarily need to be balanced. If a
        scope exit symbol is generated without a matching scope enter symbol, the default (global) scope will be
        cleared.


    **Filter function**:

            ::

                SymbolName      function(SymbolArg1[,...])

        This denotes an externally defined filter function. Note that the function name can be any valid Python
        identifier. The function can take an arbitrary number of arguments, but must return a single string which is
        the generated value for this symbol instance. Functions are passed as keyword arguments into the Grammar object
        constructor.

    **Keyword comments**:

        There are several special comment formats which can change behaviours of the grammar:

                ::

                    #clean

            No corruption for this symbol.

                ::

                    #rclean

            No corruption for this symbol or any symbols generated as part of this symbol.

                ::

                    #cfg:...

            This keyword is only valid on the first line of the file, or following a foreign grammar symbol definition.
            Following the ``cfg:`` followed by a comma separated list of one or more grammar parameters. Valid parameters
            are:

                ::

                    max-size=...

                Maximum generated size in bytes (roughly).

                ::

                    max-depth=...

                Maximum symbol recursion depth. This can be used to influence the structure of generated outputs.

    """
    __slots__ = ("_grmr", "grammar_debug", "re_refs")
    def __init__(self, grammar_str, path=".", **kwds):
        self._grmr = _alf_grammar.Grammar()
        self.grammar_debug = int(os.getenv("GRAMMAR_DEBUG", "0"), 0)
        used_kwds = set()

        self.re_refs = r"""(?x)^(?P<func>%s)\((?P<func_rest>.*)$ |
                               ^(?P<quote>[\"']).*$ |
                               ^\#\s*(?P<spec>\S*).*$ |
                               ^&(?P<file>[^\s%%s]+)\s*(?P<file_rest>.*)$ |
                               ^(?P<regex>[\[\.]).*$ |
                               ^rndint\(\s*(?P<int_a>[0-9+-]+)\s*,\s*(?P<int_b>[0-9+-]+)\s*\)\s*(?P<int_rest>.*)$ |
                               ^rndflt\(\s*(?P<flt_a>[0-9.e+-]+)\s*,\s*(?P<flt_b>[0-9.e+-]+)\s*\)\s*(?P<flt_rest>.*)$ |
                               ^(?P<sym>[^\s%%s]+)\s*(?P<sym_rest>.*)$ |
                               ^(?P<bad>.*)$""" % "|".join(kwds.keys())

        current_choice_symbol = None
        line_no = 0
        allow_cfg = True
        grammar_str = grammar_str.splitlines()
        while True:
            line_no += 1
            try:
                line = grammar_str[line_no-1]
            except IndexError:
                break
            # this messes up line numbers in the error prints.. oh well
            while line.endswith("\\"):
                line_no += 1
                try:
                    line = "%s%s" % (line[:-1], grammar_str[line_no-1])
                except IndexError:
                    raise RuntimeError("Unexpected end of input on line %d" % line_no)

            match = RE_SYM_PARSE.match(line)

            if match is None or match.group("not_name") is not None:
                raise RuntimeError("Grammar parse error on line %d" % line_no)

            if match.group("comment") is not None: # comment
                if allow_cfg:
                    self._parse_cfg(line)
                    allow_cfg = False
                continue

            if match.group("whitespace") is not None: # all whitespace
                current_choice_symbol = None
                continue

            allow_cfg = False

            name = "".join([_f for _f in match.group("ref", "star", "foreign", "choice", "concat") if _f])

            if name:
                # create an empty symbol, OR get ready to fill in a symbol that other symbols already reference
                symbol = self._grmr.name_to_symbol(name, line_no)
                assert symbol.type == 0, "Defining a symbol twice (%d)" % line_no
                current_choice_symbol = None

            if match.group("ref"):
                # Tracked symbol
                tracked = self._grmr.name_to_symbol(name[1:], line_no)
                tracked.tracked = int(match.group("ref_width"))
                if tracked.tracked > 32:
                    raise RuntimeError("References longer than 32 bytes are not supported.")
                symbol.define_reference(tracked, line_no)
                scoped = self._grmr.name_to_symbol("$%s" % name[1:], line_no) # define a scoped version too, in case it gets used
                scoped.define_scoped_reference(tracked, line_no)
                # parse the comment in case a keyword is specified
                if match.group("ref_cmt"):
                    for _ in self._parse_refs(symbol, match.group("ref_cmt"), path, kwds, used_kwds, line_no):
                        raise RuntimeError("Unexpected input on line %d" % line_no)
                    for _ in self._parse_refs(scoped, match.group("ref_cmt"), path, kwds, used_kwds, line_no):
                        raise RuntimeError("Unexpected input on line %d" % line_no)
            elif match.group("star"):
                # Star
                count, rest = match.group("count", "star_rest")
                symbol.define_star(self._parse_child(symbol, rest, path, kwds, used_kwds, line_no)[0], float(count), line_no)
            elif match.group("foreign"):
                # Foreign grammar
                filename, rest = match.group("filename", "foreign_rest")
                sub_grammar = Grammar(open(os.path.join(path, filename)).read(), path)
                if rest:
                    sub_grammar._parse_cfg(rest)
                symbol.define_foreign(sub_grammar._grmr, line_no)
            elif match.group("choice"):
                # Choice
                weight, rest = match.group("choice_weight", "choice_rest")
                symbol.define_choice(line_no)
                current_choice_symbol = symbol
                self._parse_choice(symbol, weight, rest, path, kwds, used_kwds, line_no)
            elif match.group("concat"):
                # Concatenation
                rest = match.group("concat_rest")
                symbol.define_concat(line_no)
                for child in self._parse_refs(symbol, rest, path, kwds, used_kwds, line_no):
                    symbol.add_concat(child, line_no)

            elif match.group("ccs_rest"): # starts with whitespace: continuation of previous symbol, which must be a choice symbol
                assert current_choice_symbol, "This line looks like the continuation of a choice symbol," \
                                              " but there is no current choice symbol. (%d)" % line_no
                weight, line = match.group("ccs_weight", "ccs_rest")
                self._parse_choice(current_choice_symbol, weight, line, path, kwds, used_kwds, line_no)

            else:
                raise RuntimeError("Unrecognized format parsing line %d" % line_no)

        for func in kwds:
            if func not in used_kwds:
                raise RuntimeError("Unused keyword argument: %s" % func)

        self._grmr.sanity_check()

        # populate terminal value
        grmr_pos = 0
        stack = []
        chd_pos = []
        while True:
            if not stack:
                if grmr_pos >= len(self._grmr):
                    break # done
                stack.append(self._grmr[grmr_pos])
                chd_pos.append(0)
                grmr_pos += 1
            sym = stack.pop()
            chd = chd_pos.pop()
            if sym.terminal is None:
                if sym in stack:
                    if self.grammar_debug & (1<<6):
                        sys.stderr.write("%s (%d) non-terminating by recursion\n" % (sym.name, sym.line_no))
                    sym.terminal = False
                elif chd < len(sym):
                    # recurse into children
                    stack.extend([sym, sym[chd]])
                    if self.grammar_debug & (1<<6):
                        sys.stderr.write("recursing into %s (%d) %d-th child %s (%d)\n" % (sym.name, sym.line_no, chd, sym[chd].name, sym[chd].line_no))
                    chd_pos.extend([chd + 1, 0])
                else:
                    # done with children (or no children)
                    sym.terminal = True
                    for c in sym:
                        sym.terminal = sym.terminal and c.terminal
                    if self.grammar_debug & (1<<6):
                        sys.stderr.write("%s (%d) %sterminating by children\n" % (sym.name, sym.line_no, "" if sym.terminal else "non-"))
            elif self.grammar_debug & (1<<6):
               sys.stderr.write("%s (%d) already %sterminating\n" % (sym.name, sym.line_no, "" if sym.terminal else "non-"))

    def _parse_choice(self, ccs, weight, line, path, funcs, used_funcs, line_no):
        if weight == '+':
            weight = None
        else:
            weight = float(weight)
        ccs.add_choice(self._parse_child(ccs, line, path, funcs, used_funcs, line_no)[0], weight, line_no)

    def _parse_child(self, parent, refstr, path, funcs, used_funcs, line_no, stopchars=""):
        """
        return either the symbol indicated by refstr, or an implicit concatenation
        """
        rest = ""
        gen = self._parse_refs(parent, refstr, path, funcs, used_funcs, line_no, stopchars)
        ref_a = None
        try:
            ref_a = next(gen)
            ref_b = next(gen)
        except StopIteration:
            if isinstance(ref_a, str):
                return None, ref_a
            else:
                return ref_a, rest
        if isinstance(ref_b, str):
            symbol = ref_a
            rest = ref_b
        else:
            symbol = self._grmr.new_symbol("[implicit concat]", line_no)
            symbol.define_concat(line_no)
            symbol.add_concat(ref_a, line_no)
            symbol.add_concat(ref_b, line_no)
        for child in gen:
            if rest:
                # TODO, when this is hit, figure out why and make more descriptive
                raise RuntimeError("internal error in _parse_child while parsing line %d" % line_no)
            if isinstance(child, str):
                rest = child
            else:
                symbol.add_concat(child, line_no)
        symbol.clean = parent.clean
        if symbol.clean and self.grammar_debug & (1<<5):
            sys.stderr.write("%s (%d) is clean via parent %s (%d)\n" % (symbol.name, symbol.line_no, parent.name, parent.line_no))
        return symbol, rest

    def _parse_refs(self, parent, refstr, path, funcs, used_funcs, line_no, stopchars=""):
        refstr = refstr.lstrip()
        while len(refstr) > 0 and refstr[0] not in stopchars:
            match = re.match(self.re_refs % (stopchars, stopchars), refstr)
            if match.group("quote"):
                # Parse until the matching quote character and treat the parts inside as text.
                char = match.group("quote")
                rest = refstr[1:]
                result = []
                while True:
                    m = RE_QUOTE[char].search(rest)
                    try:
                        result.append(rest[:m.start(0)])
                    except AttributeError: # when m is None
                        raise RuntimeError("Unterminated string literal ('%s') (%d)" % (refstr, line_no))
                    rest = rest[m.end(0):]
                    if m.group(0) == char:
                        # end of quote
                        break
                    else:
                        try:
                            result.append({"\\n": "\n",
                                           "\\r": "\r",
                                           "\\t": "\t",
                                           "\\v": "\v",
                                           "\\\\": "\\"}[m.group(0)])
                        except KeyError:
                            result.append(m.group(0)[1])
                result = "".join(result)
                refstr = rest.lstrip()
                yield self._grmr.text_to_symbol(result, line_no)
            elif match.group("spec") is not None: # something special
                cmd = match.group("spec")
                refstr = "" # ignore the rest
                if cmd == "clean":
                    parent.clean = True
                    if self.grammar_debug & (1<<5):
                        sys.stderr.write("%s (%d) is clean\n" % (parent.name, parent.line_no))
                elif cmd == "rclean":
                    parent.recursive_clean = True
                    if self.grammar_debug & (1<<5):
                        sys.stderr.write("%s (%d) is clean recursively\n" % (parent.name, parent.line_no))
            elif match.group("file"): # include file as text symbol
                filename, refstr = match.group("file", "file_rest")
                yield self._grmr.text_to_symbol(open(os.path.join(path, filename)).read(), line_no)
            elif match.group("func"): # external function
                func_name, refstr = match.group("func", "func_rest")
                args = []
                while True:
                    arg, refstr = self._parse_child(parent, refstr, path, funcs, used_funcs, line_no, ",)")
                    if arg is not None:
                        args.append(arg)
                    if refstr and refstr[0] == ",":
                        refstr = refstr[1:].lstrip()
                    elif refstr and refstr[0] == ")":
                        refstr = refstr[1:].lstrip()
                        break
                    else:
                        raise RuntimeError("Error parsing function arguments on line %d at: %s" % (line_no, refstr))
                symbol = self._grmr.new_symbol("%s(%s)" % (func_name, ",".join("%s/%d" % (a.name, a.id) for a in args)), line_no)
                used_funcs.add(func_name)
                symbol.define_function(funcs[func_name], args, line_no)
                yield symbol
            elif match.group("regex"):
                symbol, refstr = self._parse_regex(refstr, line_no, stopchars)
                yield symbol
            elif match.group("int_a"):
                range_start, range_end, refstr = match.group("int_a", "int_b", "int_rest")
                symbol = self._grmr.new_symbol("rndint(%s,%s)" % (range_start, range_end), line_no)
                symbol.define_rndint(int(range_start), int(range_end), line_no)
                yield symbol
            elif match.group("flt_a"):
                range_start, range_end, refstr = match.group("flt_a", "flt_b", "flt_rest")
                symbol = self._grmr.new_symbol("rndflt(%s,%s)" % (range_start, range_end), line_no)
                symbol.define_rndflt(float(range_start), float(range_end), line_no)
                yield symbol
            elif match.group("sym"):
                # A symbol name!
                name, refstr = match.group("sym", "sym_rest")
                yield self._grmr.name_to_symbol(name, line_no)
            else:
                raise RuntimeError("Parse error on line %d at \"%s\"" % (line_no, refstr))
        # special case, only possible when stopchars is defined
        if len(refstr) > 0:
            yield refstr

    def _parse_cfg(self, cfgstr):
        match = RE_CFG.match(cfgstr)
        if not match:
            return
        cfgs = [_f for _f in ((m.strip() for m in l.split("=")) for l in match.group(1).split(",")) if _f]
        for cfg, val in cfgs:
            if cfg in ("star-depth", "max-size", "max-depth"):
                setattr(self._grmr, cfg.replace("-", "_"), int(val))
            else:
                raise RuntimeError("Unknown cfg item: %s" % cfg)

    def _parse_regex(self, refs, line_no, stopchars=""):
        got = 0
        sym = self._grmr.new_symbol("[regex]", line_no)
        sym.define_regex(line_no)
        for match in RE_REGEX.finditer(refs[got:]):
            if match.start(0) != got:
                break
            count = match.group("mod")
            got = match.end(0)
            if match.group("outer") == ".":
                cls = REGEX_ALPHABET
            else:
                cls = match.group("class")
                match = RE_REGEX_RANGE.search(cls)
                while match:
                    start, _, end = match.group(0)
                    cls = cls[:match.start(0)] + "".join(chr(c) for c in range(ord(start), ord(end)+1)) + cls[match.end(0):]
                    match = RE_REGEX_RANGE.search(cls)
                if cls.startswith("^"):
                    cls = "".join(set(REGEX_ALPHABET) - set(cls[1:]))
            if not count:
                count = (1, 1)
            elif count == "*":
                count = (0, 5)
            elif count == "+":
                count = (1, 5)
            else:
                assert count.startswith("{") and count.endswith("}")
                count = count[1:-1]
                try:
                    count = int(count)
                    count = (count, count)
                except ValueError:
                    count = [int(c) for c in count.split(",")]
            sym.add_regex(cls, count[0], count[1], line_no)
        stopchars = " %s" % stopchars
        assert got == len(refs) or refs[got] in stopchars, "invalid end for regex: ('%s') (%d)" % (refs[got], line_no)
        return sym, refs[got:].lstrip()

    def generate(self, root="root"):
        """
        Generate an output based on this grammar.
        """
        res = self._grmr.generate(root)
        if self.grammar_debug & (1<<2):
            sys.stderr.write("maximum depth: %d\n" % self._grmr.last_depth_watermark)
        return res

    def __getitem__(self, key):
        return self._grmr[key]

import unittest

class GrammarTests(unittest.TestCase):

    def test_wchoice(self):
        iters = 10000
        w = WeightedChoice([(1, 1), (2, 1), (3, 1)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        for v in r.values():
            self.assertAlmostEqual(1.0*v/iters, 1.0/3, delta=.02)
        w = WeightedChoice([(1, 1), (2, 2), (3, 1)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(1.0*r[1]/iters, 0.25, delta=.02)
        self.assertAlmostEqual(1.0*r[2]/iters, 0.5, delta=.02)
        self.assertAlmostEqual(1.0*r[3]/iters, 0.25, delta=.02)
        w = WeightedChoice([(1, 3), (2, 1), (3, 1)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(1.0*r[1]/iters, 0.6, delta=.02)
        self.assertAlmostEqual(1.0*r[2]/iters, 0.2, delta=.02)
        self.assertAlmostEqual(1.0*r[3]/iters, 0.2, delta=.02)
        w = WeightedChoice([(1, 1), (2, 1), (3, 4)])
        r = {1:0, 2:0, 3:0}
        for _ in range(iters):
            r[w.choice()] += 1
        self.assertAlmostEqual(1.0*r[1]/iters, 1.0/6, delta=.02)
        self.assertAlmostEqual(1.0*r[2]/iters, 1.0/6, delta=.02)
        self.assertAlmostEqual(1.0*r[3]/iters, 2.0/3, delta=.02)

    def test_scope1(self):
        iters = 1000
        gram = "@var    10\n" \
               "var     'var_' [0-9]{2,6}\n" \
               "root    var ' { ' { var ' { ' { var ' ' $var ' } ' } $var ' } ' } $var ' ' @var #rclean"
        #               0     1     2     3     4       5      6     7      8     9        10
        w = Grammar(gram)
        r = [[0, 0, 0], [0, 0]]
        i = 0
        while i < iters:
            i += 1
            out = w.generate().split()
            self.assertNotIn(out[0], (out[2], out[4]))
            self.assertNotEqual(out[2], out[4])
            if out[5] == out[0]:
                r[0][0] += 1
            elif out[5] == out[2]:
                r[0][1] += 1
            elif out[5] == out[4]:
                r[0][2] += 1
            else:
                self.assertIn(out[5], out[:5])
            if out[7] == out[0]:
                r[1][0] += 1
            elif out[7] == out[2]:
                r[1][1] += 1
            else:
                self.assertIn(out[7], out[:3])
            self.assertEqual(out[9], out[0])
            self.assertIn(out[10], (out[0], out[2], out[4]))
        self.assertAlmostEqual(1.0*r[0][0]/iters, 1.0/3, delta=0.05)
        self.assertAlmostEqual(1.0*r[0][1]/iters, 1.0/3, delta=0.05)
        self.assertAlmostEqual(1.0*r[0][2]/iters, 1.0/3, delta=0.05)
        self.assertAlmostEqual(1.0*r[1][0]/iters, 0.5, delta=0.05)
        self.assertAlmostEqual(1.0*r[1][1]/iters, 0.5, delta=0.05)

    def test_scope2(self):
        iters = 1000
        gram = "@var    10\n" \
               "var     'var_' [0-9]{2,6}\n" \
               "root    ' { ' { var ' { ' { var ' ' $var ' } ' } $var ' } ' } @var #rclean"
        #                 0     1     2     3       4      5     6      7     8
        w = Grammar(gram)
        r = [0, 0]
        i = 0
        while i < iters:
            i += 1
            out = w.generate().split()
            self.assertNotEqual(out[1], out[3])
            if out[4] == out[3]:
                r[1] += 1
            elif out[4] == out[1]:
                r[0] += 1
            else:
                self.assertIn(out[4], out[:4])
            self.assertEqual(out[6], out[1])
            self.assertIn(out[8], (out[1], out[3]))
        self.assertAlmostEqual(1.0*r[0]/iters, 0.5, delta=0.05)
        self.assertAlmostEqual(1.0*r[1]/iters, 0.5, delta=0.05)

    def test_funcs(self):
        iters = 10
        gram = "root    *10     func #rclean\n" \
               "func    10      'z' zero(nuvar) '\\n'\n" \
               "        10      'a' alpha(alvar , '*,' rep) '\\n'\n" \
               "        1       nuvar '\\n'\n" \
               "        1       alvar '\\n'\n" \
               "nuvar           'n' [0-9]{6}\n" \
               "alvar           'c' [a-z]{6}\n" \
               "rep             [0-9]"
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
        gram = "var     + 'a'\n" \
               "        + 'b'\n" \
               "        + 'c'\n" \
               "root    + var # rclean\n" \
               "        + 'd'"
        w = Grammar(gram)
        r = {'a':0, 'b':0, 'c':0, 'd':0}
        i = 0
        while i < iters:
            i += 1
            v = w.generate()
            r[v] += 1
        for v in r.values():
            self.assertAlmostEqual(1.0*v/iters, 0.25, delta=0.03)

    def test_basic(self):
        w = Grammar("root    ok #\n"
                    "ok      '1'")
        self.assertEqual(w.generate(), "1")
        w = Grammar("root   a #rclean\n"
                    "a      '1234' [a-z] b\n"
                    "b      1 c\n"
                    "       1 d\n"
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
        w = Grammar("root    '\\\\' #rclean")
        g = w.generate()
        self.assertEqual(g, "\\")
        w = Grammar("root    \"\\\\\" #rclean")
        g = w.generate()
        self.assertEqual(g, "\\")

    def test_quo2(self):
        w = Grammar("root    '\\'' #rclean")
        g = w.generate()
        self.assertEqual(g, "'")
        w = Grammar("root    \"\\\"\" #rclean")
        g = w.generate()
        self.assertEqual(g, "\"")

    def test_quo3(self):
        w = Grammar("root    '\\'some' #rclean")
        g = w.generate()
        self.assertEqual(g, "'some")
        w = Grammar("root    \"\\\"some\" #rclean")
        g = w.generate()
        self.assertEqual(g, "\"some")

    def test_quo4(self):
        w = Grammar("root    'some\\'' #rclean")
        g = w.generate()
        self.assertEqual(g, "some'")
        w = Grammar("root    \"some\\\"\" #rclean")
        g = w.generate()
        self.assertEqual(g, "some\"")

    def test_quo5(self):
        # unbalanced parens, end paren is escaped .. should raise
        with self.assertRaises(RuntimeError):
            w = Grammar(r"root    '\\\\\\\' #rclean")
        with self.assertRaises(RuntimeError):
            w = Grammar(r'root    "\\\\\\\" #rclean')

    def test_quo6(self):
        w = Grammar(r"root    '\\\\\\\'\\' #rclean")
        g = w.generate()
        self.assertEqual(g, "\\\\\\'\\")
        w = Grammar(r'root    "\\\\\\\"\\" #rclean')
        g = w.generate()
        self.assertEqual(g, "\\\\\\\"\\")

    def test_quo7(self):
        w = Grammar("root    \"'some\" #rclean")
        g = w.generate()
        self.assertEqual(g, "'some")
        w = Grammar("root    '\"some' #rclean")
        g = w.generate()
        self.assertEqual(g, "\"some")

    def test_quo8(self):
        w = Grammar("root    \"'\" #rclean")
        g = w.generate()
        self.assertEqual(g, "'")
        w = Grammar("root    \"''\" #rclean")
        g = w.generate()
        self.assertEqual(g, "''")
        w = Grammar("root    \"'''\" #rclean")
        g = w.generate()
        self.assertEqual(g, "'''")
        w = Grammar("root    '\"' #rclean")
        g = w.generate()
        self.assertEqual(g, "\"")
        w = Grammar("root    '\"\"' #rclean")
        g = w.generate()
        self.assertEqual(g, "\"\"")
        w = Grammar("root    '\"\"\"' #rclean")
        g = w.generate()
        self.assertEqual(g, "\"\"\"")

    def test_quo9(self):
        #right: "<h5 id='id824837' onload='chat(\'id705147\',1,\' width=\\\'2pt\\\'\')'>"
        #                                                        ^  -- esc() --   ^
        #wrong: "<h5 id='id824837' onload='chat(\'id705147\',1,\\\' width=\\\'2pt\'\')'>"
        #                                                      ^  -- esc() --   ^
        w = Grammar("@id 8\n"
                    "root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\" #rclean\n"
                    "id     'id' [0-9]{6}\n"
                    "func   \"chat('\" id \"',\" [0-9] \",'\" esc(\" width='2pt'\") \"')\"\n"
                    , esc=lambda x:re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(w.generate(), r"^<h5 id='id[0-9]{6}' onload='chat\(\\'id[0-9]{6}"
                                       r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")
        # same grammar with '@id' in chat() instead of 'id'
        w = Grammar("@id 8\n"
                    "root   \"<h5 id='\" id \"' onload='\" esc(func) \"'>\" #rclean\n"
                    "id     'id' [0-9]{6}\n"
                    "func   \"chat('\" @id \"',\" [0-9] \",'\" esc(\" width='2pt'\") \"')\"\n"
                    , esc=lambda x:re.sub(r"('|\\)", r"\\\1", x))
        self.assertRegex(w.generate(), r"^<h5 id='(id[0-9]{6})' onload='chat\(\\'\1"
                                       r"\\',[0-9],\\' width=\\\\\\'2pt\\\\\\'\\'\)'>$")

    def test_func_nest_tracked(self):
        w = Grammar("@id 1\n"
                    "root   id a(b(@id)) #rclean\n"
                    "id     'i'\n"
                    , a=lambda x:"a" + x, b=lambda x:"b" + x)
        self.assertEqual(w.generate(), "iabi")

    def test_tracked1(self):
        w = Grammar("@id 3\n"
                    "root    id '\\n' esc(\"'\" @id \"'\") #rclean\n"
                    "id      'id' [0-9]",
                    esc=lambda x:re.sub(r"'", "\\'", x))
        defn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "\\'%s\\'" % defn)

    def test_tracked2(self):
        w = Grammar("@id 3\n"
                    "root    id '\\n' esc('not', @id) #rclean\n"
                    "id      'id' [0-9]",
                    esc=lambda x,y:x)
        defn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(use, "not")

    def test_tracked3(self):
        w = Grammar("@id 3\n"
                    "root    esc(id) '\\n' @id #rclean\n"
                    "id      'id' [0-9]",
                    esc=lambda x:"%s\n%s" % (x, ''.join('%02x'%i for i in x.encode())))
        defn, hexn, use = w.generate().splitlines()
        self.assertRegex(defn, r"^id[0-9]$")
        self.assertEqual(''.join('%02x'%i for i in defn.encode()), hexn)
        self.assertEqual(defn, use)

    def test_tracked4(self):
        w = Grammar("@id 3\n"
                    "root    @id #rclean\n"
                    "id      'id' [0-9]")
        self.assertEqual(w.generate(), "   ")

    def test_tracked5(self):
        w = Grammar("@id 3\n"
                    "root    esc(id) @id #rclean\n"
                    "id      'id' [0-9]",
                    esc=lambda x:"")
        self.assertRegex(w.generate(), r"^id[0-9]$")

    def test_tracked6(self):
        w = Grammar("@id 4\n"
                    "root   ids #rclean\n"
                    "ids    *10000  id '\\n'\n"
                    "id     'id' [0-9]{2}")
        with self.assertRaises(RuntimeError) as cm:
            w.generate()
        self.assertIn("generate unique tracked symbol", cm.exception.args[0].lower())
        self.assertIn("possibilities", cm.exception.args[0].lower())
        w = Grammar("@id 4\n"
                    "root   ids #rclean\n"
                    "ids    *50 id '\\n'\n"
                    "id     'id' [0-9]{2}")
        w.generate()

    def test_max_depth(self):
        global test_max_depth_var
        test_max_depth_var = 0
        def filt():
            global test_max_depth_var
            test_max_depth_var += 1
            if test_max_depth_var > 10:
                raise Exception("max-depth did not limit recursion")
            return "a"
        w = Grammar("#cfg:max-depth=10\n"
                    "root            A   #rclean\n"
                    "A               filt() A",
                    filt=filt)
        v = w.generate()
        self.assertRegex(v, r"^a+$")
        self.assertAlmostEqual(len(v), 10, delta=3)

    def test_hard_depth(self):
        global test_max_depth_var
        test_max_depth_var = 0
        def filt():
            global test_max_depth_var
            test_max_depth_var += 1
            if test_max_depth_var > 10000:
                raise Exception("test_hard_depth:fail")
            return ""
        w = Grammar("root            A   #rclean\n"
                    "A               filt() A",
                    filt=filt)
        with self.assertRaises(RuntimeError) as cm:
            w.generate()
        self.assertIn("recursion", cm.exception.args[0].lower())
        test_max_depth_var = 0
        def filt():
            global test_max_depth_var
            test_max_depth_var += 1
            if test_max_depth_var > 7500:
                raise Exception("test_hard_depth:pass")
            return ""
        w = Grammar("root            A   #rclean\n"
                    "A               filt() A",
                    filt=filt)
        with self.assertRaises(Exception) as cm:
            w.generate()
        self.assertEqual("test_hard_depth:pass", cm.exception.args[0])

    def test_tyson(self):
        w = Grammar('root   [0-1]{1} "]" #rclean')
        o = w.generate()
        self.assertIn(o, ["0]", "1]"])

suite = unittest.TestLoader().loadTestsFromTestCase(GrammarTests)

