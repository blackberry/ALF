################################################################################
# Description: Grammar based parser
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
from .grammr2 import BinSymbol, ChoiceSymbol, ConcatSymbol, FuncSymbol, RefSymbol, RegexSymbol, RepeatSymbol, TextSymbol

class _slushydict(dict):
    """hashable, but not immutable"""
    __slots__ = tuple()
    def __hash__(self):
        return hash(frozenset(self.items()))
    def copy(self):
        return _slushydict(dict.copy(self))


class _cstate(object):
    __slots__ = ("c", "out")

    def __init__(self, c):
        self.c, self.out = c, None

    def set_out(self, v):
        assert self.out is None
        self.out = v

    def add(self, l, st, ptr):
        l.add((self, st, ptr))

    @staticmethod
    def repr_or_None(value):
        if value is not None:
            return "%x" % id(value)
        else:
            return "None"

    def __repr__(self):
        return "<_cstate(%s,%s) at %x>" % (self.c, _cstate.repr_or_None(self.out), id(self))


class _rstate(_cstate):
    __slots__ = ("a", "b", "name", "out2")

    def __init__(self, name, a, b, cont):
        _cstate.__init__(self, None)
        self.a, self.b = a, b
        self.out2 = cont
        self.name = name

    def add(self, l, st, ptr):
        try:
            ctr = st[id(self)]
        except KeyError:
            ctr = st[id(self)] = 0
        if ctr >= self.a and (self.b is None or ctr <= self.b):
            st2 = st.copy()
            count = st2.pop(id(self)) # record loop exit statistics and reset counter
            try:
                st2[self.name] = st2[self.name] + (count,)
            except KeyError:
                st2[self.name] = (count,)
            self.out.add(l, st2, ptr)
        ctr += 1
        st[id(self)] = ctr
        if self.b is None or ctr <= self.b:
            self.out2.add(l, st, ptr)

    def __repr__(self):
        return "<_rstate({%s,%s},%s,%s) at %x>" % (self.a, self.b, _cstate.repr_or_None(self.out2), _cstate.repr_or_None(self.out), id(self))


class _bstate(_cstate):
    __slots__ = ("name", "out2")

    def __init__(self, name, out1=None, out2=None):
        _cstate.__init__(self, None)
        self.name, self.out, self.out2 = name, out1, out2

    def add(self, l, st, ptr):
        name, i, j = self.name
        for idx, out in ((i, self.out), (j, self.out2)):
            if idx is not None:
                count = st.get((name, idx), 0) + 1
            # record branch statistics
            s = st.copy()
            if idx is not None:
                s[(name, idx)] = count
            out.add(l, s, ptr)

    def __repr__(self):
        return "<_bstate(%s,%s) at %x>" % (_cstate.repr_or_None(self.out), _cstate.repr_or_None(self.out), id(self))


class GrammarCracker(object):
    """
    Takes a grammar instance, and uses that to 'crack' generated data
    and return a new grammar instance with weights updated to reflect
    what was seen in the data.  This means the returned grammar instance
    should generate testcases similar to data.
    """
    _matchstate = _cstate(None)
    _concat = object()
    _lparen = object()
    _rparen = object()

    def __init__(self, grammar):
        # build NFA for cracking
        stack = []
        self.copy0 = grammar.copy0
        for c in GrammarCracker._traverse_grammar_postfix(grammar):
            if c is GrammarCracker._concat:
                start2, out2 = stack.pop()
                start1, out1 = stack.pop()
                for l in out1:
                    l(start2)
                stack.append([start1, out2])
            elif isinstance(c, _bstate):
                start2, out2 = stack.pop()
                start1, out1 = stack.pop()
                s = _bstate(c.name, start1, start2)
                stack.append([s, out1 + out2])
            elif isinstance(c, tuple):
                a, b, name = c
                start, out = stack.pop()
                s = _rstate(name, a, b, start)
                for l in out:
                    l(s)
                stack.append([s, [s.set_out]])
            else:
                s = _cstate(c)
                stack.append([s, [s.set_out]])
        self._start, out = stack.pop()
        assert not stack
        for l in out:
            l(GrammarCracker._matchstate)

    def crack(self, s):
        """Run NFA to determine whether it matches s."""
        clist = set()
        self._start.add(clist, _slushydict(), 0)
        #log.debug("(init) %s", clist)
        while clist and isinstance(clist, set):
            clist = GrammarCracker._step(clist, s)
        if isinstance(clist, set):
            return None # no match
        else:
            # clist is decision history, use it to update weights and return a new Grammar instance
            r = self.copy0()
            choices = set()
            for nm, stats in clist.items():
                if isinstance(nm, tuple):
                    # Choice
                    nm, idx = nm
                    r.symtab[nm].weights[idx] += stats
                    if idx > 1:
                        r.symtab[nm].weights[idx - 1] -= stats
                    choices.add(nm)
                else:
                    # Repeat
                    #r.symtab[nm].mode = sum(stats) / len(stats)
                    r.symtab[nm].a = min(stats)
                    r.symtab[nm].b = max(stats)
            for nm in choices:
                r.symtab[nm].total = sum(r.symtab[nm].weights)
            return r

    @staticmethod
    def _step(clist, inp):
        """
        Step the NFA from the states in clist past the current input ptr, to create next NFA state set nlist.
        """
        nlist = set()
        for s, st, ptr in clist:
            if s is GrammarCracker._matchstate and ptr >= len(inp):
                # success
                # could be that there's more than one match if we run longer
                # ... any way to tell if one is better than another?
                return st
            if s.c is not None:
                bite = s.c(inp, ptr)
                if bite > 0:
                    s.out.add(nlist, st, ptr + bite)
        #log.debug("(%s) %s -> %s", inp, clist, nlist)
        return nlist

    @staticmethod
    def _traverse_grammar_infix(grammar, start="root"):
        togo = [start]
        while togo:
            sym = togo.pop()
            if type(sym) in (_bstate, tuple) or sym in (GrammarCracker._lparen, GrammarCracker._rparen):
                yield sym
                continue
            sym = grammar.symtab[sym]
            sym_t = type(sym)
            if sym_t in (BinSymbol, TextSymbol):
                yield sym.match
            elif sym_t is ConcatSymbol:
                togo.append(GrammarCracker._rparen)
                togo.extend(reversed(sym))
                yield GrammarCracker._lparen
            elif sym_t is ChoiceSymbol:
                if sym.cracker is not None:
                    yield sym.cracker.match
                else:
                    togo.append(GrammarCracker._rparen)
                    sub = []
                    for i, s in enumerate(sym.values):
                        if i == 1:
                            sub.append(_bstate((sym.name, 0, i)))
                        elif i != 0:
                            sub.append(_bstate((sym.name, None, i)))
                        sub.extend(s)
                    togo.extend(reversed(sub))
                    yield GrammarCracker._lparen
            elif sym_t is FuncSymbol:
                if sym.fname == "rndflt":
                    yield sym.match_rndflt
                elif sym.fname == "rndflt":
                    yield sym.match_rndint
                else:
                    # TODO ... support a user-supplied reverse function?
                    raise Exception("Cannot parse with grammars using external function calls.")
            elif sym_t is RefSymbol:
                togo.append(sym.ref)
            elif sym_t is RepeatSymbol:
                if sym.a == 0 and sym.b == 0:
                    continue
                togo.append((sym.a, sym.b, sym.name))
                togo.append(GrammarCracker._rparen)
                togo.extend(reversed(sym))
                yield GrammarCracker._lparen
            elif sym_t is RegexSymbol:
                togo.append(GrammarCracker._rparen)
                togo.extend(reversed(sym.parts))
                yield GrammarCracker._lparen
            else:
                raise Exception("Can't crack using symbol %s of type %s" % (sym.name, sym_t))

    @staticmethod
    def _traverse_grammar_postfix(grammar, start="root"):
        """
        Convert infix regexp re to postfix notation.
        Insert explicit concatenation operator.
        """
        nalt, natom = [], 0
        parens = []
        for c in GrammarCracker._traverse_grammar_infix(grammar, start):
            if c is GrammarCracker._lparen:
                if natom > 1:
                    natom -= 1
                    yield GrammarCracker._concat
                parens.append((nalt, natom))
                nalt, natom = [], 0
            elif isinstance(c, _bstate):
                assert natom > 0
                for _ in range(natom-1):
                    yield GrammarCracker._concat
                natom = 0
                nalt.append(c)
            elif c is GrammarCracker._rparen:
                assert len(parens)
                assert natom > 0
                for _ in range(natom-1):
                    yield GrammarCracker._concat
                for i in reversed(nalt):
                    yield i
                nalt, natom = parens.pop()
                natom += 1
            elif isinstance(c, tuple):
                assert natom > 0
                yield c
            else:
                if natom > 1:
                    yield GrammarCracker._concat
                else:
                    natom += 1
                yield c
        assert not parens
        for _ in range(natom-1):
            yield GrammarCracker._concat
        for i in reversed(nalt):
            yield i


