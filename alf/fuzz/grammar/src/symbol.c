/*
 * Copyright 2014 BlackBerry Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include <Python.h>
#include <structmember.h>
#include "alf_grammar.h"
#include "symbol.h"
#include "gen_state.h"
#include "grammar.h"
#include "wchoice.h"
#include "rnd.h"

static int
_generate_abstract(PyObject *s, void *vg)
{
    PyErr_Format(PyExc_RuntimeError, "Can't generate an abstract symbol! %s (L%d)", SYMOBJ(s)->name, SYMOBJ(s)->line_no);
    return -1;
}

static int
Symbol_init(SymbolObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"id", "name", "line_no", NULL};
    const char *name;

    PyObject_GC_UnTrack(self);
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "isi", kwlist, &self->id, &name, &self->line_no))
        return -1;
    self->name = strdup(name);
    if (!self->name) {
        PyErr_NoMemory();
        return -1;
    }
    self->tracked = 0;
    self->recursive_clean = 0;
    self->clean = 0;
    self->terminal = -1;
    ODBGN(D_REF, "++ symbol: %s/%d (L%d)\n", self->name, self->id, self->line_no);
    self->type = SYM_TYPE_ABSTRACT;
    self->_generate = _generate_abstract;
    PyObject_GC_Track(self);
    return 0;
}

static void
Symbol_dealloc(SymbolObject *self)
{
    ODBGN(D_REF, "-- symbol: %s/%d (L%d)\n", self->name, self->id, self->line_no);
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_clear((PyObject *)self);
    if (self->name) {
        free(self->name);
        self->name = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}

int
_generate(SymbolObject *s, void *vg)
{
    gen_state_t *g = vg;
    int local_rstate = 0;
    int reference_tries;

    DBGN(D_GEN, "%s/%d (L%d)\n", s->name, s->id, s->line_no);
    if (s->tracked) {
        if (gen_state_start_tracking_instance(g, (PyObject *)s))
            return -1;
    } else if (s->clean || s->recursive_clean || g->clean) {
        if (gen_state_start_clean(g, (PyObject *)s))
            return -1;
    } else if (!g->tracking && !gen_state_hit_depth(g)) {
        /*
         pre-generate mutations
         */
        if (chance(.001))
            return 0; // skip entirely

        if (!gen_state_hit_limit(g) && !gen_state_hit_depth(g)) {
            if (chance(.001)) {
                if (_generate(s, g)) // extra of same symbol (before this one)
                    return -1;
            }
            if (chance(.001)) {
                if (_generate(SYMOBJ(_random_symbol(GRMOBJ(g->grammar))), g)) // extra of another symbol, before this one
                    return -1;
            }

            // AM - random char
            if (chance(.001)) {
                const char c = (char)rnd(128);
                if (gen_state_write(g, &c, 1))
                    return -1;
            }
        }

        if (g->rstate == 0 && chance(.03)) {
            local_rstate = 1;
            g->rstate = 1;
            g->rsym = (PyObject *)s;
            if (g->rpoint >= 6) {
                PyErr_Format(PyExc_RuntimeError, "gen_state_t.rpoints overflow %d", __LINE__);
                return -1;
            }
            g->rpoints[g->rpoint++] = gen_state_tell(g);
        } else if (g->rstate == 1 && g->rsym == (PyObject *)s && chance(.3)) {
            g->rstate = 2;
            if (g->rpoint >= 6) {
                PyErr_Format(PyExc_RuntimeError, "gen_state_t.rpoints overflow %d", __LINE__);
                return -1;
            }
            g->rpoints[g->rpoint++] = gen_state_tell(g);
            local_rstate = 2;
        }
    }

    reference_tries = 100;
    while (1) {
        g->depth += 1;
        if (g->depth > g->depth_watermark)
            g->depth_watermark = g->depth;
        if (g->depth > 10000) {
            PyErr_Format(PyExc_RuntimeError, "hit hard recursion limit");
            return -1;
        }
        // only respect depth here for non-terminals
        if ((s->terminal || !(gen_state_hit_depth(g) || gen_state_hit_limit(g))) && s->_generate((PyObject *)s, g))
            return -1;
        g->depth -= 1;

        if (g->tracking || s->clean || g->clean) {
            if (s->tracked) {
                int r = gen_state_end_tracking_instance(g, (PyObject *)s);
                if (r == -1)
                    return -1;
                if (r) {
                    reference_tries--;
                    if (!reference_tries) {
                        PyErr_Format(PyExc_RuntimeError, "Failed to generate unique tracked symbol! Does it have enough possibilities? %s (L%d)", s->name, s->line_no);
                        return -1;
                    }
                    continue;
                }
            }
            if (gen_state_end_clean(g, (PyObject *)s))
                return -1;
            return 0;
        } else {
            break;
        }
    }
    // tracking/clean symbols will return from above loop rather than break out.
    if (gen_state_hit_depth(g))
        return 0;

    if (local_rstate == 1) {
        if (g->rstate == 1) {
            if (chance(.01)) {
                // No matching inner symbol was chosen, but we can repeat what happened inside this symbol anyway!
                // (good for testing the scanner, if not the parser, right?)
                if (g->rpoint >= 5) {
                    PyErr_Format(PyExc_RuntimeError, "gen_state_t.rpoints overflow %d", __LINE__);
                    return -1;
                }
                g->rpoints[g->rpoint++] = gen_state_tell(g);
                g->rpoints[g->rpoint++] = gen_state_tell(g);
                g->rstate = 9;
            }
        } else {
            if (g->rstate != 3) {
                PyErr_Format(PyExc_RuntimeError, "OOPS! %d", g->rstate);
                return -1;
            }
            g->rstate = 4;
        }
        if (g->rpoint >= 6) {
            PyErr_Format(PyExc_RuntimeError, "gen_state_t.rpoints overflow %d", __LINE__);
            return -1;
        }
        g->rpoints[g->rpoint++] = gen_state_tell(g);
    } else if (local_rstate == 2) {
        g->rstate = 3;
        if (g->rpoint >= 6) {
            PyErr_Format(PyExc_RuntimeError, "gen_state_t.rpoints overflow %d", __LINE__);
            return -1;
        }
        g->rpoints[g->rpoint++] = gen_state_tell(g);
    }

    if (!gen_state_hit_limit(g) && !gen_state_hit_depth(g) && chance(.001)) {
        if (_generate(SYMOBJ(_random_symbol(GRMOBJ(g->grammar))), g)) // extra of another symbol, after this one
            return -1;
    }
    return 0;
}

static int
_generate_star(PyObject *s, void *vg)
{
    gen_state_t *g = (gen_state_t *)vg;
    if (SYMOBJ(s)->clean || g->clean || (!gen_state_hit_limit(g) && !gen_state_hit_depth(g))) {
        if (gen_state_inc_star_depth(g, s))
            return -1;

        if (!SYMOBJ(s)->clean && !g->clean && chance(.1)) {
            // For the repetition generator, I think it helps to do self sometimes...
            DBGN(D_GEN, "-> *1 self %s/%d (L%d)\n", SYMOBJ(SYMOBJ(s)->data.star.child)->name, SYMOBJ(SYMOBJ(s)->data.star.child)->id, SYMOBJ(SYMOBJ(s)->data.star.child)->line_no);
            if (_generate(SYMOBJ(s), g))
                return -1;
            if (_generate(SYMOBJ(SYMOBJ(s)->data.star.child), g))
                return -1;
        } else if (!SYMOBJ(s)->clean && !g->clean && chance(.09)) {
            DBGN(D_GEN, "-> *1 %s/%d self (L%d)\n", SYMOBJ(SYMOBJ(s)->data.star.child)->name, SYMOBJ(SYMOBJ(s)->data.star.child)->id, SYMOBJ(SYMOBJ(s)->data.star.child)->line_no);
            if (_generate(SYMOBJ(SYMOBJ(s)->data.star.child), g))
                return -1;
            if (_generate(SYMOBJ(s), g))
                return -1;
        } else {
            // When sym.star_depth is 1, the average is recommended_count.  For every nesting, the average is halved.
            int count, i;

            //old:
            //count = rnd(rnd(SYMOBJ(s)->data.star.recommended_count * powl(2, GRMOBJ(g->grammar)->star_depth - (int)gen_state_get_star_depth(g, s))));

            //new: eliminate star_depth parameter, average is recommended_count/2 at depth=1, * 0.75 at each nesting
            count = rnd(SYMOBJ(s)->data.star.recommended_count);
            for (i = 1; i < gen_state_get_star_depth(g, s); i++)
                count = rnd(count);
            if (PyErr_Occurred())
                return -1;

            DBGN(D_GEN, "-> *%d %s/%d (L%d)\n", count, SYMOBJ(SYMOBJ(s)->data.star.child)->name, SYMOBJ(SYMOBJ(s)->data.star.child)->id, SYMOBJ(SYMOBJ(s)->data.star.child)->line_no);
            for (i = 0; i < count; i++) {
                if (!SYMOBJ(s)->clean && !g->clean && (gen_state_hit_limit(g) || gen_state_hit_depth(g)))
                    break;
                if (_generate(SYMOBJ(SYMOBJ(s)->data.star.child), g))
                    return -1;
            }
        }

        if (gen_state_dec_star_depth(g, s)) {
            return -1;
        }
    }
    return 0;
}

static PyObject *
choose_choice(SymbolObject *s)
{
    if (s->type != SYM_TYPE_CHOICE) {
        PyErr_Format(PyExc_TypeError, "'Symbol' object is not a choice");
        return NULL;
    }
    return wchoice_choice((WeightedChoiceObject *)s->data.obj);
}

static int
_generate_choice(PyObject *s, void *g)
{
    int res;
    PyObject *obj;

    obj = choose_choice(SYMOBJ(s));
    if (!obj)
        return -1;
    res = _generate(SYMOBJ(obj), (gen_state_t *)g);
    Py_DECREF(obj);
    return res;
}

static int
_generate_concat(PyObject *s, void *vg)
{
    gen_state_t *g = vg;
    int i;

    for (i = 0; i < SYMOBJ(s)->data.concat.n_children; i++) {
        if (!g->tracking && !SYMOBJ(s)->clean && !g->clean && chance(.001)) {
            i += rnd(SYMOBJ(s)->data.concat.n_children); // skip part of this concatenation
        } else {
            if (_generate(SYMOBJ(SYMOBJ(s)->data.concat.children[i]), g))
                return -1;
        }
    }
    return 0;
}

static int
_generate_regex(PyObject *s, void *vg)
{
    int i, count;
    gen_state_t *g = (gen_state_t *)vg;
    regex_pt_t *p;
    const char *pystr;
    unsigned int pystrlen;

    DBGN(D_GEN, "-> regex has %d parts, each generating: [", SYMOBJ(s)->data.regex.n_parts);
    for (i = 0; i < SYMOBJ(s)->data.regex.n_parts; i++) {
        p = SYMOBJ(s)->data.regex.parts + i;
        if (gen_state_hit_limit(g) || gen_state_hit_depth(g))
            count = p->min_count;
        else
            count = rnd(rnd(p->max_count - p->min_count + 1)) + p->min_count;
        if (i)
            PDBGN(D_GEN, ",");
        PDBGN(D_GEN, "%d", count);
        pystr = PyBytes_AS_STRING(p->charset);
        pystrlen = PyBytes_GET_SIZE(p->charset);
        for ( ;count > 0; count--) {
            // TODO: unicode
            if (gen_state_write(g, &pystr[rnd(pystrlen)], 1))
                return -1;
        }
    }
    PDBGN(D_GEN, "]\n");
    return 0;
}

static int
_generate_text(PyObject *s, void *g)
{
    PyObject *t = SYMOBJ(s)->data.obj;
    if (gen_state_write((gen_state_t *)g, PyBytes_AS_STRING(t), PyBytes_GET_SIZE(t)))
        return -1;
    return 0;
}

static int
_generate_foreign(PyObject *s, void *g)
{
    PyObject *res;
    const char *strres;
    int status;

    res = generate_real(GRMOBJ(SYMOBJ(s)->data.foreign.grammar), SYMOBJ(s)->data.foreign.start_sym);
    if (!res)
        return -1;
    strres = PyBytes_AsString(res);
    if (!strres) {
        Py_DECREF(res);
        return -1;
    }
    status = gen_state_write((gen_state_t *)g, strres, PyBytes_GET_SIZE(res));
    Py_DECREF(res);
    return status;
}

static int
_generate_reference(PyObject *s, void *g)
{
    int tracked_sz = SYMOBJ(SYMOBJ(s)->data.obj)->tracked, i;

    // remember the reference
    if (gen_state_mark_tracking_reference((gen_state_t *)g, SYMOBJ(s)->data.obj))
        return -1;
    // generate enough space in the output
    for (i = 0; i < tracked_sz; i++) {
        if (gen_state_write((gen_state_t *)g, " ", 1))
            return -1;
    }
    return 0;
}

static int
_generate_rndint(PyObject *s, void *g)
{
    char buf[256];
    int len;

    len = snprintf(buf, 256, "%d", rnd(SYMOBJ(s)->data.rndint.b) + SYMOBJ(s)->data.rndint.a);
    if (len < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    if (gen_state_write((gen_state_t *)g, buf, len))
        return -1;
    return 0;
}

static int
_generate_rndflt(PyObject *s, void *g)
{
    char buf[256];
    int len;

    len = snprintf(buf, 256, "%lf", rndl_inc(SYMOBJ(s)->data.rndflt.b) + SYMOBJ(s)->data.rndflt.a);
    if (len < 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    if (gen_state_write((gen_state_t *)g, buf, len))
        return -1;
    return 0;
}

/*
 This symbol filters its children through a python function...  where anything is possible.

 functions are generated differently than other symbols:
 - each arg is generated into the output, but the start/end of each arg is recorded for later
 - after references (@symbols) are resolved, then all the functions can be called
 - function output replaces the args in the output (may be bigger or smaller than arg length)
 - function args may contain other function calls, so when function return replaces it's args,
   need to check if this falls within the range of another function arg, and if so repair the range
 */
static int
_generate_function(PyObject *s, void *g)
{
    PyObject *res, *l;
    int status, i, func_cookie, has_ref, defer_depth;
    int *args, nargs;

    // generate arg values
    l = PySequence_Fast(SYMOBJ(s)->data.func.args, "Error enumerating function args");
    if (!l)
        return -1;
    nargs = PySequence_Fast_GET_SIZE(l);
    args = (int *)malloc(sizeof(int) * (nargs + 1));
    if (!args) {
        Py_DECREF(l);
        PyErr_NoMemory();
        return -1;
    }
    args[0] = gen_state_tell(g);
    func_cookie = gen_state_enter_function(g);
    defer_depth = ((gen_state_t *)g)->nfuncs;
    for (i = 0; i < PySequence_Fast_GET_SIZE(l); i++) {
        status = _generate(SYMOBJ(PySequence_Fast_GET_ITEM(l, i)), g);
        if (status) {
            Py_DECREF(l);
            free(args);
            return -1;
        }
        args[i+1] = gen_state_tell(g); // mark end of this arg
    }
    Py_DECREF(l);
    has_ref = gen_state_leave_function(g, func_cookie);
    if (has_ref) {
        // function call must be deferred until after references are generated
        return gen_state_defer_function(g, s, nargs, args, defer_depth);
    } else {
        // call function now
        const char *strres;
        res = call_func_now(s, g, nargs, args);
        gen_state_backtrack(g, args[0]);
        free(args);
        if (!res)
            return -1;
        strres = PyBytes_AsString(res);
        if (!strres) {
            Py_DECREF(res);
            return -1;
        }
        status = gen_state_write((gen_state_t *)g, strres, PyBytes_GET_SIZE(res));
        Py_DECREF(res);
        return status;
    }
}

PyObject *
call_func_now(PyObject *s, const void *g, int nargs, const int args[])
{
#if PY_MAJOR_VERSION >= 3
    PyObject *nres;
#endif
    PyObject *res, *pyargs = PyTuple_New(nargs);
    int i;

    for (i = 0; i < nargs; i++) {
        res = gen_state_slice(g, args[i], args[i+1]);
        if (!res) {
            Py_DECREF(pyargs);
            return NULL;
        }
        PyTuple_SET_ITEM(pyargs, i, res);
    }
    res = PyObject_CallObject(SYMOBJ(s)->data.func.f, pyargs);
    Py_DECREF(pyargs);
    if (!res)
        return NULL;
#if PY_MAJOR_VERSION >= 3
    nres = PyUnicode_AsEncodedString(res, "utf-8", "strict");
    Py_DECREF(res);
    if (!nres)
        return NULL;
    return nres;
#else
    // return result
    return res;
#endif
}

static PyObject *
define_star(SymbolObject *self, PyObject *args)
{
    PyObject *child;
    double count;
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_star(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "O!di", &SymbolType, &child, &count, &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    Py_INCREF(child);
    self->type = SYM_TYPE_STAR;
    self->data.star.recommended_count = count;
    self->data.star.child = child;
    self->_generate = _generate_star;
    self->line_no = line_no;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: star *%.1lf %s/%d (L%d)\n", self->name, count, SYMOBJ(child)->name, SYMOBJ(child)->id, line_no);
    Py_RETURN_NONE;
}

static PyObject *
define_choice(SymbolObject *self, PyObject *args)
{
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_choice(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "i", &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    self->data.obj = PyObject_CallObject((PyObject *)&WeightedChoiceType, NULL);
    if (!self->data.obj) {
        PyObject_GC_Track(self);
        return NULL;
    }
    self->type = SYM_TYPE_CHOICE;
    self->_generate = _generate_choice;
    self->line_no = line_no;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: choice (L%d)\n", self->name, line_no);
    Py_RETURN_NONE;
}

static PyObject *
define_concat(SymbolObject *self, PyObject *args)
{
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_concat(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "i", &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    self->data.concat.children = NULL;
    self->data.concat.n_children = 0;
    self->type = SYM_TYPE_CONCAT;
    self->_generate = _generate_concat;
    self->line_no = line_no;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: concatenation (L%d)\n", self->name, line_no);
    Py_RETURN_NONE;
}

static PyObject *
define_regex(SymbolObject *self, PyObject *args)
{
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_regex(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "i", &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    self->data.regex.parts = NULL;
    self->data.regex.n_parts = 0;
    self->type = SYM_TYPE_REGEX;
    self->_generate = _generate_regex;
    self->line_no = line_no;
    self->terminal = 1;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: regex (L%d)\n", self->name, line_no);
    Py_RETURN_NONE;
}

int
define_text(SymbolObject *self, PyObject *text, int line_no)
{
    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_text(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return -1;
    }
    PyObject_GC_UnTrack(self);
    Py_INCREF(text);
    self->type = SYM_TYPE_TEXT;
    self->data.obj = text;
    self->_generate = _generate_text;
    self->line_no = line_no;
    self->terminal = 1;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: '%s' (L%d)\n", self->name, PyBytes_AS_STRING(text), line_no);
    return 0;
}

static PyObject *
define_foreign(SymbolObject *self, PyObject *args)
{
    PyObject *g;
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_foreign(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "O!i", &GrammarType, &g, &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    Py_INCREF(g);
    self->data.foreign.start_sym = PyDict_GetItemString(GRMOBJ(g)->sym_dict, "root");
    if (!self->data.foreign.start_sym) {
        PyObject_GC_Track(self);
        Py_DECREF(g);
        PyErr_Format(PyExc_KeyError, "Start symbol not defined: root");
        return NULL;
    }
    self->type = SYM_TYPE_FOREIGN;
    self->data.foreign.grammar = g;
    Py_INCREF(self->data.foreign.start_sym);
    self->_generate = _generate_foreign;
    self->line_no = line_no;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: foreign (L%d)\n", self->name, line_no);
    Py_RETURN_NONE;
}

static PyObject *
define_reference(SymbolObject *self, PyObject *args)
{
    int line_no;
    PyObject *tracked;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_reference(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "O!i", &SymbolType, &tracked, &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    self->type = SYM_TYPE_REFERENCE;
    self->data.obj = tracked;
    Py_INCREF(tracked);
    self->_generate = _generate_reference;
    self->line_no = line_no;
    self->terminal = 1;
    SYMOBJ(tracked)->terminal = 1;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: reference (L%d)\n", self->name, line_no);
    Py_RETURN_NONE;
}

static PyObject *
define_scoped_reference(SymbolObject *self, PyObject *args)
{
    int line_no;
    PyObject *tracked;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_scoped_reference(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "O!i", &SymbolType, &tracked, &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    self->type = SYM_TYPE_SCOPED_REF;
    self->data.obj = tracked;
    Py_INCREF(tracked);
    self->_generate = gen_state_generate_scoped_instance;
    self->line_no = line_no;
    self->clean = 1;
    self->terminal = 1;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, "dd %s: scoped ref (L%d)\n", self->name, line_no);
    Py_RETURN_NONE;
}

static PyObject *
define_rndint(SymbolObject *self, PyObject *args)
{
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_rndint(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "iii", &self->data.rndint.a, &self->data.rndint.b, &line_no))
        return NULL;
    self->data.rndint.b -= self->data.rndint.a - 1;
    self->type = SYM_TYPE_RNDINT;
    self->_generate = _generate_rndint;
    self->line_no = line_no;
    self->terminal = 1;
    Py_RETURN_NONE;
}

static PyObject *
define_rndflt(SymbolObject *self, PyObject *args)
{
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_rndflt(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "ddi", &self->data.rndflt.a, &self->data.rndflt.b, &line_no))
        return NULL;
    self->data.rndflt.b -= self->data.rndflt.a;
    self->type = SYM_TYPE_RNDFLT;
    self->_generate = _generate_rndflt;
    self->line_no = line_no;
    self->terminal = 1;
    Py_RETURN_NONE;
}

static PyObject *
define_function(SymbolObject *self, PyObject *args)
{
    int line_no;

    if (self->type != SYM_TYPE_ABSTRACT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting abstract symbol in define_function(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    PyObject_GC_UnTrack(self);
    if (!PyArg_ParseTuple(args, "OOi", &self->data.func.f, &self->data.func.args, &line_no)) {
        PyObject_GC_Track(self);
        return NULL;
    }
    if (!PyCallable_Check(self->data.func.f)) {
        PyErr_Format(PyExc_RuntimeError, "Expecting a callable function (L%d)", line_no);
        PyObject_GC_Track(self);
        return NULL;
    }
    if (!PySequence_Check(self->data.func.args)) {
        PyErr_Format(PyExc_RuntimeError, "Expecting sequence (L%d)", line_no);
        PyObject_GC_Track(self);
        return NULL;
    }
    Py_INCREF(self->data.func.f);
    Py_INCREF(self->data.func.args);
    self->type = SYM_TYPE_FUNCTION;
    self->_generate = _generate_function;
    self->line_no = line_no;
    PyObject_GC_Track(self);
    Py_RETURN_NONE;
}

static PyObject *
add_choice(SymbolObject *self, PyObject *args)
{
    PyObject *child, *t, *nargs;
    double weight;
    int line_no;

    if (self->type != SYM_TYPE_CHOICE) {
        PyErr_Format(PyExc_RuntimeError, "Expecting choice symbol in add_choice(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "O!di", &SymbolType, &child, &weight, &line_no)) {
        PyErr_Clear();
        if (!PyArg_ParseTuple(args, "O!Oi", &SymbolType, &child, &t, &line_no))
            return NULL;
        if (t != Py_None) {
            PyErr_Format(PyExc_TypeError, "float or None is required");
            return NULL;
        }
        switch (SYMOBJ(child)->type) {
            case SYM_TYPE_ABSTRACT:
                PyErr_Format(PyExc_RuntimeError, "'%s' must be defined prior to use with '+' (L%d)", SYMOBJ(child)->name, line_no);
                return NULL;
            case SYM_TYPE_CHOICE:
                weight = ((WeightedChoiceObject *)SYMOBJ(child)->data.obj)->total;
                break;
            default:
                weight = 1;
                break;
        }
    }
    nargs = Py_BuildValue("Od", child, weight);
    if (!nargs)
        return NULL;
    PyObject_GC_UnTrack(self);
    t = wchoice_append((WeightedChoiceObject *)self->data.obj, nargs);
    PyObject_GC_Track(self);
    Py_DECREF(nargs);
    if (!t)
        return NULL;
    Py_DECREF(t);
    ODBGN(D_PRS, " \\(%s choice) %lg %s\n", self->name, weight, SYMOBJ(child)->name);
    Py_RETURN_NONE;
}

static PyObject *
add_concat(SymbolObject *self, PyObject *args)
{
    PyObject *child;
    void *newobj;
    int line_no;

    if (self->type != SYM_TYPE_CONCAT) {
        PyErr_Format(PyExc_RuntimeError, "Expecting concatenation symbol in add_concat(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "O!i", &SymbolType, &child, &line_no))
        return NULL;
    PyObject_GC_UnTrack(self);
    self->data.concat.n_children++;
    newobj = realloc(self->data.concat.children, self->data.concat.n_children * sizeof(PyObject *));
    if (!newobj) {
        self->data.concat.n_children--;
        PyObject_GC_Track(self);
        PyErr_NoMemory();
        return NULL;
    }
    self->data.concat.children = (PyObject **)newobj;
    self->data.concat.children[self->data.concat.n_children-1] = child;
    Py_INCREF(child);
    PyObject_GC_Track(self);
    ODBGN(D_PRS, " \\(%s concat) %s\n", self->name, SYMOBJ(child)->name);
    Py_RETURN_NONE;
}

static PyObject *
add_regex(SymbolObject *self, PyObject *args)
{
    PyObject *charset;
    int min, max, line_no;
    void *newobj;

    if (self->type != SYM_TYPE_REGEX) {
        PyErr_Format(PyExc_RuntimeError, "Expecting regex symbol in add_regex(), got type %d for symbol %s (L%d)", self->type, self->name, self->line_no);
        return NULL;
    }
    if (!PyArg_ParseTuple(args, "Siii", &charset, &min, &max, &line_no)) {
        PyObject *unicode;
        PyErr_Clear();
        if (!PyArg_ParseTuple(args, "Uiii", &unicode, &min, &max, &line_no))
            return NULL;
        charset = PyUnicode_AsEncodedString(unicode, "utf-8", "strict");
        if (!charset)
            return NULL;
    } else {
        Py_INCREF(charset);
    }
    PyObject_GC_UnTrack(self);
    self->data.regex.n_parts++;
    newobj = realloc(self->data.regex.parts, self->data.regex.n_parts * sizeof(regex_pt_t));
    if (!newobj) {
        self->data.regex.n_parts--;
        PyObject_GC_Track(self);
        Py_DECREF(charset);
        PyErr_NoMemory();
        return NULL;
    }
    self->data.regex.parts = (regex_pt_t *)newobj;
    self->data.regex.parts[self->data.regex.n_parts-1].charset = charset;
    self->data.regex.parts[self->data.regex.n_parts-1].min_count = min;
    self->data.regex.parts[self->data.regex.n_parts-1].max_count = max;
    PyObject_GC_Track(self);
    ODBGN(D_PRS, " \\(%s regex) [%s]{%d,%d}\n", self->name, PyBytes_AS_STRING(charset), min, max);
    Py_RETURN_NONE;
}

static PyObject *
get_terminal(SymbolObject *self, void *data)
{
    switch (self->terminal) {
        case -1:
            Py_RETURN_NONE;
        case 0:
            Py_RETURN_FALSE;
        case 1:
            Py_RETURN_TRUE;
        default:
            PyErr_Format(PyExc_RuntimeError, "Unhandled value for 'terminal' attribute (%d)", self->terminal);
            return NULL;
    }
}

static int
set_terminal(SymbolObject *self, PyObject *value, void *data)
{
    if (value == Py_True)
        self->terminal = 1;
    else if (value == Py_False)
        self->terminal = 0;
    else if (value == Py_None)
        self->terminal = -1;
    else {
        PyErr_SetString(PyExc_TypeError, "attribute value type must be bool or None");
        return -1;
    }
    return 0;
}

static Py_ssize_t
Symbol_length(SymbolObject *self)
{
    switch (self->type) {
        case SYM_TYPE_STAR:
            return 1;
        case SYM_TYPE_CONCAT:
            return self->data.concat.n_children;
        case SYM_TYPE_CHOICE:
            return wchoice_len((WeightedChoiceObject *)self->data.obj);
        case SYM_TYPE_FUNCTION:
            return PySequence_Length(self->data.func.args);
    }
    return 0;
}

static PyObject *
Symbol_getitem(SymbolObject *self, Py_ssize_t i)
{
    PyObject *ret = NULL;

    switch (self->type) {
        case SYM_TYPE_STAR:
            if (i == 0)
                ret = self->data.star.child;
            break;
        case SYM_TYPE_CONCAT:
            if (i < self->data.concat.n_children)
                ret = self->data.concat.children[i];
            break;
        case SYM_TYPE_CHOICE:
            if (i < wchoice_len((WeightedChoiceObject *)self->data.obj))
                ret = ((WeightedChoiceObject *)self->data.obj)->data[i].obj;
            break;
       case SYM_TYPE_FUNCTION:
            return PySequence_GetItem(self->data.func.args, i);
    }
    if (ret) {
        Py_INCREF(ret);
        return ret;
    }
    PyErr_Format(PyExc_IndexError, "child index out of range");
    return NULL;
}

static int
Symbol_traverse(SymbolObject *self, visitproc visit, void *arg)
{
    int i;

    switch (self->type) {
        case SYM_TYPE_STAR:
            if (self->data.star.child)
                Py_VISIT(self->data.star.child);
            break;
        case SYM_TYPE_REFERENCE:
        case SYM_TYPE_SCOPED_REF:
        case SYM_TYPE_CHOICE:
        case SYM_TYPE_TEXT:
            if (self->data.obj)
                Py_VISIT(self->data.obj);
            break;
        case SYM_TYPE_CONCAT:
            for (i = 0; i < self->data.concat.n_children; i++)
                if (self->data.concat.children[i])
                    Py_VISIT(self->data.concat.children[i]);
            break;
        case SYM_TYPE_FOREIGN:
            if (self->data.foreign.start_sym)
                Py_VISIT(self->data.foreign.start_sym);
            if (self->data.foreign.grammar)
                Py_VISIT(self->data.foreign.grammar);
            break;
        case SYM_TYPE_REGEX:
            for (i = 0; i < self->data.regex.n_parts; i++)
                if (self->data.regex.parts[i].charset)
                    Py_VISIT(self->data.regex.parts[i].charset);
            break;
        case SYM_TYPE_FUNCTION:
            if (self->data.func.f)
                Py_VISIT(self->data.func.f);
            if (self->data.func.args)
                Py_VISIT(self->data.func.args);
        default:
            break;
    }
    return 0;
}

static int
Symbol_clear(SymbolObject *self)
{
    int i;

    switch (self->type) {
        case SYM_TYPE_STAR:
            Py_CLEAR(self->data.star.child);
            break;
        case SYM_TYPE_REFERENCE:
        case SYM_TYPE_SCOPED_REF:
        case SYM_TYPE_CHOICE:
        case SYM_TYPE_TEXT:
            Py_CLEAR(self->data.obj);
            break;
        case SYM_TYPE_CONCAT:
            for (i = 0; i < self->data.concat.n_children; i++)
                Py_CLEAR(self->data.concat.children[i]);
            self->data.concat.n_children = 0;
            if (self->data.concat.children) {
                free(self->data.concat.children);
                self->data.concat.children = NULL;
            }
            break;
        case SYM_TYPE_FOREIGN:
            Py_CLEAR(self->data.foreign.start_sym);
            Py_CLEAR(self->data.foreign.grammar);
            break;
        case SYM_TYPE_REGEX:
            for (i = 0; i < self->data.regex.n_parts; i++)
                Py_CLEAR(self->data.regex.parts[i].charset);
            self->data.regex.n_parts = 0;
            if (self->data.regex.parts) {
                free(self->data.regex.parts);
                self->data.regex.parts = NULL;
            }
            break;
        case SYM_TYPE_FUNCTION:
            Py_CLEAR(self->data.func.f);
            Py_CLEAR(self->data.func.args);
        default:
            break;
    }
    return 0;
}

static PyMethodDef Symbol_methods[] = {
    {"define_star", (PyCFunction)define_star, METH_VARARGS, NULL},
    {"define_choice", (PyCFunction)define_choice, METH_VARARGS, NULL},
    {"define_concat", (PyCFunction)define_concat, METH_VARARGS, NULL},
    {"define_regex", (PyCFunction)define_regex, METH_VARARGS, NULL},
    {"define_foreign", (PyCFunction)define_foreign, METH_VARARGS, NULL},
    {"define_reference", (PyCFunction)define_reference, METH_VARARGS, NULL},
    {"define_scoped_reference", (PyCFunction)define_scoped_reference, METH_VARARGS, NULL},
    {"define_rndint", (PyCFunction)define_rndint, METH_VARARGS, NULL},
    {"define_rndflt", (PyCFunction)define_rndflt, METH_VARARGS, NULL},
    {"define_function", (PyCFunction)define_function, METH_VARARGS, NULL},

    {"add_choice", (PyCFunction)add_choice, METH_VARARGS, NULL},
    {"add_concat", (PyCFunction)add_concat, METH_VARARGS, NULL},
    {"add_regex", (PyCFunction)add_regex, METH_VARARGS, NULL},
    {"choose_choice", (PyCFunction)choose_choice, METH_NOARGS, NULL},

    {NULL} // Sentinel
};

static PyMemberDef Symbol_members[] = {
    {"clean", T_BOOL, offsetof(SymbolObject, clean), 0, "If true, mutations will not be applied to this symbol nor "
                                                        "direct children. They will always be generated as defined."},
    {"recursive_clean", T_BOOL, offsetof(SymbolObject, recursive_clean), 0, "If true, mutations will not be applied "
                                                                            "to this symbol nor any children "
                                                                            "(recursively). They will always be "
                                                                            "generated as defined."},
    {"tracked", T_INT, offsetof(SymbolObject, tracked), 0, "Non-zero will generate unique values for this symbol, "
                                                           "and @symbol references will be populated after "
                                                           "generation. The value should be the maximum space the "
                                                           "symbol could generate in the output."},
    {"name", T_STRING, offsetof(SymbolObject, name), 0, "Name of this symbol."},
    {"type", T_UBYTE, offsetof(SymbolObject, type), READONLY, "Defined type of this symbol."},
    {"line_no", T_INT, offsetof(SymbolObject, line_no), READONLY, "Line number of first symbol occurrence."},
    {"id", T_INT, offsetof(SymbolObject, id), READONLY, "Unique identifier of this symbol in the grammar."},
    {NULL} // Sentinel
};

static PyGetSetDef Symbol_getset[] = {
    {"terminal", (getter)get_terminal, (setter)set_terminal, "Whether or not this symbol definition is recursive"},
    {NULL} // Sentinel
};

static PySequenceMethods Symbol_seq_methods = {
    (lenfunc)Symbol_length,             // sq_length
    0,                                  // sq_concat
    0,                                  // sq_repeat
    (ssizeargfunc)Symbol_getitem,       // sq_item
    0,                                  // sq_ass_item
    0,                                  // sq_contains
    0,                                  // sq_inplace_concat
    0,                                  // sq_inplace_repeat
};

PyTypeObject SymbolType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_alf_grammar.Symbol",              // tp_name
    sizeof(SymbolObject),               // tp_basicsize
    0,                                  // tp_itemsize
    (destructor)Symbol_dealloc,         // tp_dealloc
    0,                                  // tp_print
    0,                                  // tp_getattr
    0,                                  // tp_setattr
    0,                                  // tp_compare
    0,                                  // tp_repr
    0,                                  // tp_as_number
    &Symbol_seq_methods,                // tp_as_sequence
    0,                                  // tp_as_mapping
    0,                                  // tp_hash
    0,                                  // tp_call
    0,                                  // tp_str
    0,                                  // tp_getattro
    0,                                  // tp_setattro
    0,                                  // tp_as_buffer
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC, // tp_flags
    "Symbol objects",                   // tp_doc
    (traverseproc)Symbol_traverse,      // tp_traverse
    (inquiry)Symbol_clear,              // tp_clear
    0,                                  // tp_richcompare
    0,                                  // tp_weaklistoffset
    0,                                  // tp_iter
    0,                                  // tp_iternext
    Symbol_methods,                     // tp_methods
    Symbol_members,                     // tp_members
    Symbol_getset,                      // tp_getset
    0,                                  // tp_base
    0,                                  // tp_dict
    0,                                  // tp_descr_get
    0,                                  // tp_descr_set
    0,                                  // tp_dictoffset
    (initproc)Symbol_init,              // tp_init
    0,                                  // tp_alloc
    0,                                  // tp_new
};

