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
#include <string.h>
#include "alf_grammar.h"
#include "gen_state.h"
#include "grammar.h"
#include "symbol.h"
#include "rnd.h"

int
gen_state_init(gen_state_t *g, PyObject *grammar, int max_size)
{
    memset(g, 0, sizeof(gen_state_t));
    g->rpoint = 1;
    g->grammar = grammar;
    g->sym_state = (_sym_state_t *)calloc(GRMOBJ(grammar)->max_id, sizeof(_sym_state_t));
    if (!g->sym_state) {
        PyErr_NoMemory();
        return -1;
    }
    g->max_size = max_size;
    g->buf = (char *)malloc(STRBUF_SZ);
    if (!g->buf) {
        free(g->sym_state);
        PyErr_NoMemory();
        return -1;
    }
    g->alloced = STRBUF_SZ;
    g->printed_limit = 0;
    g->printed_depth = 0;
    g->in_function = 0;
    g->has_reference = 0;
    g->nfuncs = 0;
    g->funcs = NULL;
    Py_INCREF(g->grammar);
    return 0;
}

static int
gen_state_resize_buf(gen_state_t *g, int len)
{
    char *newbuf;
    int alloced = g->alloced;

    if (len <= g->alloced)
        return 0;

    while (alloced < len)
        alloced += STRBUF_SZ / 2;

    // expand
    newbuf = realloc(g->buf, alloced);
    if (!newbuf) {
        PyErr_NoMemory();
        return -1;
    }
    g->buf = newbuf;
    g->alloced = alloced;
    return 0;
}

int
gen_state_write(gen_state_t *g, const char *s, unsigned int len)
{
    if (gen_state_resize_buf(g, g->used + len))
        return -1;
    memcpy(g->buf + g->used, s, len);
    g->used += len;
    return 0;
}

int
gen_state_defer_function(gen_state_t *g, PyObject *s, int nargs, int args[], int defer_depth)
{
    _deferred_func_t *df;
    df = (_deferred_func_t *)realloc(g->funcs, (g->nfuncs+1) * sizeof(_deferred_func_t));
    if (!df) {
        PyErr_NoMemory();
        return -1;
    }
    g->funcs = df;
    if (defer_depth != g->nfuncs)
        memmove(&g->funcs[defer_depth+1], &g->funcs[defer_depth], (g->nfuncs - defer_depth) * sizeof(_deferred_func_t));
    g->nfuncs++;
    df = &g->funcs[defer_depth];
    df->sym = s;
    df->nargs = nargs;
    df->args = args;
    Py_INCREF(s);
    return 0;
}

PyObject *
gen_state_slice(const gen_state_t *g, int from, int to)
{
    if (to > g->used || from > to) {
        PyErr_Format(PyExc_RuntimeError, "Invalid arguments to gen_state_slice(%d,%d) with %d bytes in buffer", from, to, g->used);
        return NULL;
    }
#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromStringAndSize(g->buf + from, to - from);
#else
    return PyBytes_FromStringAndSize(g->buf + from, to - from);
#endif
}

int
gen_state_tell(const gen_state_t *g)
{
    return g->used;
}

int
gen_state_enter_function(gen_state_t *g)
{
    int res = g->in_function;
    g->in_function = 1;
    if (!res)
        return -1;
    res = g->has_reference;
    g->has_reference = 0;
    return res;
}

int
gen_state_leave_function(gen_state_t *g, int func_cookie)
{
    int has_ref = g->has_reference;
    switch (func_cookie) {
        case -1:
            g->has_reference = 0;
            g->in_function = 0;
            break;
        case 0:
            g->has_reference = has_ref;
            break;
        case 1:
            g->has_reference = 1;
            break;
    }
    return has_ref;
}

char
gen_state_hit_depth(gen_state_t *g)
{
    int max_depth = GRMOBJ(g->grammar)->max_depth;
    char res = max_depth && (g->depth >= max_depth);
    DBGN(D_LMT, "max_depth:%d g->depth:%d == %d\n", max_depth, g->depth, res);
    if (res && !g->printed_depth) {
        if (g->max_size > 100)
            DBGN(D_GEN, "Hit the depth limit of %d at filesize %d\n", g->depth, gen_state_tell(g));
        g->printed_depth = 1;
    }
    return res;
}

char
gen_state_hit_limit(gen_state_t *g)
{
    char res = (g->max_size >= 0) && (gen_state_tell(g) >= g->max_size);
    DBGN(D_LMT, "g->max_size:%d gen_state_tell(g):%d == %d\n", g->max_size, gen_state_tell(g), res);
    if (res && !g->printed_limit) {
        if (g->max_size > 100)
            DBGN(D_GEN, "Hit the size limit at %d\n", gen_state_tell(g));
        g->printed_limit = 1;
    }
    return res;
}

static _sym_state_t *
_get_sym_state(gen_state_t *g, PyObject *sym)
{
    _sym_state_t *u;
    int id;

    id = SYMOBJ(sym)->id;
    if (id >= GRMOBJ(g->grammar)->max_id) {
        PyErr_Format(PyExc_RuntimeError, "Invalid symbol id %d for symbol %s (L%d)", id, SYMOBJ(sym)->name, SYMOBJ(sym)->line_no);
        return NULL;
    }
    u = &g->sym_state[id];
    if (!u->sym) {
        Py_INCREF(sym);
        u->sym = sym;
        u->tracking_start = -1;
    }
    return u;
}

int
gen_state_inc_star_depth(gen_state_t *g, PyObject *s)
{
    _sym_state_t *u = _get_sym_state(g, s);
    if (!u)
        return -1;
    u->count++;
    return 0;
}

int
gen_state_get_star_depth(gen_state_t *g, PyObject *s)
{
    _sym_state_t *u = _get_sym_state(g, s);
    if (!u)
        return 0;
    return u->count;
}

int
gen_state_dec_star_depth(gen_state_t *g, PyObject *s)
{
    _sym_state_t *u = _get_sym_state(g, s);
    if (!u)
        return -1;
    if (u->count == 0) {
        PyErr_Format(PyExc_RuntimeError, "Negative star depth. You've gone off the deep end.");
        return -1;
    }
    u->count--;
    return 0;
}

int
gen_state_backtrack(gen_state_t *g, int pos)
{
    g->used = pos;
    return 0;
}

int
gen_state_start_tracking_instance(gen_state_t *g, PyObject *s)
{
    _sym_state_t *u = _get_sym_state(g, s);
    if (!u)
        return -1;
    if (u->tracking_start != -1) {
        PyErr_Format(PyExc_RuntimeError, "Can't nest tracked symbols! %s (L%d)", SYMOBJ(s)->name, SYMOBJ(s)->line_no);
        return -1;
    }
    g->tracking++;
    u->tracking_start = gen_state_tell(g);
    return 0;
}

static int
_init_scopes(_sym_state_t *u, int scope)
{
    int i;

    if (!u->descoped_instances) {
        u->descoped_instances = PySet_New(NULL);
        if (!u->descoped_instances)
            return -1;
    }
    if (!u->scopes) {
        u->scopes = (PyObject **)calloc(scope + 1, sizeof(PyObject *));
        if (!u->scopes) {
            PyErr_NoMemory();
            return -1;
        }
        for (i = 0; i <= scope; i++) {
            u->scopes[i] = PySet_New(NULL);
            if (!u->scopes[i])
                return -1;
        }
    }
    return 0;
}

int
gen_state_inc_scope(PyObject *unused, void *vg)
{
    gen_state_t *g = (gen_state_t *)vg;
    int i;
    void *newobj;

    (void)unused;
    for (i = GRMOBJ(g->grammar)->max_id - 1; i >= 0; i--) {
        if (!g->sym_state[i].sym || !g->sym_state[i].scopes)
            continue;
        newobj = realloc(g->sym_state[i].scopes, sizeof(PyObject *) * (g->scope + 2));
        if (!newobj) {
            PyErr_NoMemory();
            goto fail;
        }
        g->sym_state[i].scopes = newobj;
        g->sym_state[i].scopes[g->scope + 1] = PySet_New(NULL);
        if (!g->sym_state[i].scopes[g->scope + 1])
            goto fail;
    }
    g->scope++;
    return 0;
fail:
    // either failed to realloc i or failed to create a set at i
    for (i++; i < GRMOBJ(g->grammar)->max_id; i++) {
        if (!g->sym_state[i].sym || !g->sym_state[i].scopes)
            continue;
        Py_CLEAR(g->sym_state[i].scopes[g->scope + 1]);
    }
    return -1;
}

int
gen_state_dec_scope(PyObject *unused, void *vg)
{
    gen_state_t *g = (gen_state_t *)vg;
    int i;
    PyObject *descoped, *added;

    (void)unused;
    for (i = GRMOBJ(g->grammar)->max_id - 1; i >= 0; i--) {
        if (!g->sym_state[i].sym || !g->sym_state[i].scopes)
            continue;
        descoped = g->sym_state[i].scopes[g->scope];
#if 0
        if (g->scope) {
            void *newobj = realloc(g->sym_state[i].scopes, sizeof(PyObject *) * g->scope);
            if (!newobj) {
                PyErr_NoMemory();
                return -1;
            }
            g->sym_state[i].scopes = newobj;
        }
#endif
        added = PyNumber_InPlaceOr(g->sym_state[i].descoped_instances, descoped);
        if (!added)
            return -1;
        Py_DECREF(g->sym_state[i].descoped_instances);
        g->sym_state[i].descoped_instances = added;
        g->sym_state[i].n_scoped_instances -= PySet_GET_SIZE(descoped);
        if (g->scope) {
            Py_DECREF(descoped);
            g->sym_state[i].scopes[g->scope] = NULL;
        } else {
            PySet_Clear(descoped); // never destroy the outermost scope
        }
    }
    if (g->scope)
        g->scope--;
    return 0;
}

static int
_instance_unique(const _sym_state_t *u, PyObject *o, int scope)
{
    int i, r;
    r = PySet_Contains(u->descoped_instances, o);
    if (r)
        return r;
    for (i = 0; i <= scope; i++) {
        r = PySet_Contains(u->scopes[i], o);
        if (r)
            return r;
    }
    return 0;
}

int
gen_state_generate_scoped_instance(PyObject *s, void *vg)
{
    gen_state_t *g = vg;
    int i, j;
    PyObject *l, *src;

    _sym_state_t *u = _get_sym_state(g, SYMOBJ(s)->data.obj);
    if (!u)
        return -1;
    DBGN(D_GEN, "-> %d instances of %s in scope (scope level %d)\n", u->n_scoped_instances, SYMOBJ(SYMOBJ(s)->data.obj)->name, g->scope);
    if (!u->descoped_instances || !u->scopes || !u->n_scoped_instances) {
        PyErr_Format(PyExc_RuntimeError, "No instances in scope to generate! %s (L%d)", SYMOBJ(s)->name, SYMOBJ(s)->line_no);
        return -1;
    }
    i = rnd(u->n_scoped_instances);
    for (j = 0; j <= g->scope; j++) {
        i -= PySet_GET_SIZE(u->scopes[j]);
        if (i < 0)
            break;
    }
    if (j > g->scope) {
        PyErr_Format(PyExc_RuntimeError, "Out of scopes. instances=%d,scope=%d", u->n_scoped_instances, g->scope);
        return -1;
    }
    l = PySequence_Fast(u->scopes[j], "Error with scoped variable");
    if (!l)
        return -1;
    src = PySequence_Fast_GET_ITEM(l, rnd(PySequence_Fast_GET_SIZE(l)));
    i = gen_state_write(g, PyBytes_AS_STRING(src), PyBytes_GET_SIZE(src));
    Py_DECREF(l);
    return i;
}

int
gen_state_end_tracking_instance(gen_state_t *g, PyObject *s)
{
    int sz, r;
    _sym_state_t *u;
    void *newobj;

    if (!g->tracking) {
        PyErr_Format(PyExc_RuntimeError, "Not tracking any symbols! %s (L%d)", SYMOBJ(s)->name, SYMOBJ(s)->line_no);
        return -1;
    }
    u = _get_sym_state(g, s);
    if (!u)
        return -1;
    if (u->tracking_start == -1) {
        PyErr_Format(PyExc_RuntimeError, "Not tracking this symbol! %s (L%d)", SYMOBJ(s)->name, SYMOBJ(s)->line_no);
        return -1;
    }
    sz = gen_state_tell(g) - u->tracking_start;
    if (sz > SYMOBJ(s)->tracked) {
        PyErr_Format(PyExc_RuntimeError, "Symbol reference is the wrong size. Expecting %d, got %d. %s (L%d)",
            SYMOBJ(s)->tracked, sz, SYMOBJ(s)->name, SYMOBJ(s)->line_no);
        return -1;
    }
    if (_init_scopes(u, g->scope))
        return -1;
    newobj = PyBytes_FromStringAndSize(g->buf + u->tracking_start, sz);
    if (!newobj)
        return -1;
    r = _instance_unique(u, newobj, g->scope);
    switch (r) {
        case -1:
            Py_DECREF(newobj);
            return -1;
        case 1:
            DBGN(D_TRK, "-> duplicate tracked reference, try another %s -> '%s' (%u instances)\n", SYMOBJ(s)->name, PyBytes_AS_STRING(newobj), PySet_GET_SIZE(u->descoped_instances));
            Py_DECREF(newobj);
            if (gen_state_backtrack(g, u->tracking_start))
                return -1;
            return 1;
        case 0:
            if (PySet_Add(u->scopes[g->scope], newobj)) {
                Py_DECREF(newobj);
                return -1;
            }
            u->n_scoped_instances++;
            Py_DECREF(newobj);
            DBGN(D_GEN, "-> Got %d instances of %s (%d in scope)\n", PySet_GET_SIZE(u->descoped_instances) + u->n_scoped_instances, SYMOBJ(s)->name, u->n_scoped_instances);
            u->tracking_start = -1;
            g->tracking--;
            return 0;
    }
    Py_DECREF(newobj);
    PyErr_Format(PyExc_RuntimeError, "Unhandled case in gen_state_end_tracking_instance(): %d", r);
    return -1;
}

int
gen_state_mark_tracking_reference(gen_state_t *g, PyObject *s)
{
    _sym_state_t *u;
    void *newobj;

    u = _get_sym_state(g, s);
    if (!u)
        return -1;
    u->n_tracked_references++;
    newobj = realloc(u->tracked_references, u->n_tracked_references * sizeof(int));
    if (!newobj) {
        u->n_tracked_references--;
        PyErr_NoMemory();
        return -1;
    }
    u->tracked_references = (int *)newobj;
    u->tracked_references[u->n_tracked_references - 1] = gen_state_tell(g);
    if (g->in_function)
        g->has_reference = 1;
    return 0;
}

static int
gen_state_expand_references(gen_state_t *g)
{
    int i, j;
    _sym_state_t *u;
    PyObject *src;

    while (g->scope)
        if (gen_state_dec_scope(NULL, g))
            return -1;
    // once more for the outermost scope
    if (gen_state_dec_scope(NULL, g))
        return -1;
    for (i = GRMOBJ(g->grammar)->max_id - 1; i >= 0; i--) {
        u = &g->sym_state[i];
        if (!u->sym)
            continue;
        // have references and instances -> good
        // have instances but no references -> don't care
        // have references but no instances -> can't do anything...
        if (u->n_tracked_references && u->descoped_instances && PySet_GET_SIZE(u->descoped_instances)) {
            PyObject *l = PySequence_Fast(u->descoped_instances, "Error with tracked variable");
            if (!l)
                return -1;
            for (j = 0; j < u->n_tracked_references; j++) {
                src = PySequence_Fast_GET_ITEM(l, rnd(PySequence_Fast_GET_SIZE(l)));
                memcpy(g->buf + u->tracked_references[j], PyBytes_AS_STRING(src), PyBytes_GET_SIZE(src));
            }
            Py_DECREF(l);
        }
    }
    return 0;
}

int
gen_state_start_clean(gen_state_t *g, PyObject *s)
{
    if (g->clean) {
        if (g->clean == s) {
            PyErr_Format(PyExc_RuntimeError, "Internal error: recursive definition of #clean symbol? %s (L%d)", SYMOBJ(s)->name, SYMOBJ(s)->line_no);
            return -1;
        }
        return 0;
    }
    if (!SYMOBJ(s)->clean && !SYMOBJ(s)->recursive_clean) {
        PyErr_Format(PyExc_RuntimeError, "Internal error: expected a #clean symbol %s (L%d)", SYMOBJ(s)->name, SYMOBJ(s)->line_no);
        return -1;
    }
    if (!SYMOBJ(s)->recursive_clean)
        return 0;
    DBGN(D_GEN, ">> rclean %s/%d (L%d)\n", SYMOBJ(s)->name, SYMOBJ(s)->id, SYMOBJ(s)->line_no);
    g->clean = s;
    return 0;
}

int
gen_state_end_clean(gen_state_t *g, PyObject *s)
{
    if (g->clean == s) {
        DBGN(D_GEN, "<< rclean %s/%d (L%d)\n", SYMOBJ(s)->name, SYMOBJ(s)->id, SYMOBJ(s)->line_no);
        g->clean = NULL;
    }
    return 0;
}

static void
memcpy_upto(char *buf, int to_off, int from_off, int len, int out_sz)
{
    int wouldbe_sz = to_off + len;
    if (wouldbe_sz > out_sz) {
        len = out_sz - to_off;
        if (len <= 0)
            return;
    }
    memcpy(buf + to_off, buf + from_off, len);
}

static int
gen_state_call_funcs(gen_state_t *g)
{
    int i, j, argen, argst, diff;
    PyObject *res;
    const char *strres;
    _deferred_func_t *df;

    while (g->nfuncs) {
        g->nfuncs--;
        df = &g->funcs[g->nfuncs];
        argst = df->args[0];
        argen = df->args[df->nargs];
        DBGN(D_GEN, "calling deferred func %s (arglen=%d starting at %08X)\n", SYMOBJ(df->sym)->name, argen - argst, argst);
        res = call_func_now(df->sym, g, df->nargs, df->args);
        free(df->args);
        Py_DECREF(df->sym);
        if (!res)
            return -1;
        strres = PyBytes_AsString(res);
        if (!strres) {
            Py_DECREF(res);
            return -1;
        }
        diff = PyBytes_GET_SIZE(res) - (argen - argst);
        DBGN(D_GEN, " -> result is %d (%d difference)\n", PyBytes_GET_SIZE(res), diff);
        if (diff > 0 && gen_state_resize_buf(g, g->used + diff)) {
            Py_DECREF(res);
            return -1;
        }
        // replace buf[argst:argen] with strres
        memmove(&g->buf[argen + diff], &g->buf[argen], g->used - argen);
        g->used += diff;
        memcpy(&g->buf[argst], strres, PyBytes_GET_SIZE(res));
        Py_DECREF(res);
        // fix up other funcs / rpoints based on this diff.
        for (i = g->rpoint - 1; i >= 0; i--) {
            if (g->rpoints[i] >= argen) {
                // TODO, if the rpoint is within [argst:argen] .. what to do? (applies to non-deferred too)
                g->rpoints[i] += diff;
            }
        }
        for (i = g->nfuncs - 1; i >= 0; i--) {
            df = &g->funcs[i];
            if (df->args[df->nargs] >= argen) { // one of this funcs args contains the result of this one
                for (j = 0; j < df->nargs; j++) {
                    if (df->args[j+1] >= argen)
                        df->args[j+1] += diff;
                }
            }
        }
        // don't need to worry about references... they've already been expanded.
    }
    return 0;
}

PyObject *
gen_state_expand(gen_state_t *g)
{
    PyObject *nr;
    int chop = 0;

    // Chop off the end of the string at a random point within the string.
    // This is a bit unnatural and against the spirit of symmetry,
    // but it's important for testing EOF handling in the *scanner*.
    if (0 && chance(.05)) {
        DBGN(D_GEN, "CHOP!\n");
        chop = 1;
    }

    if (gen_state_expand_references(g))
        return NULL;

    if (gen_state_call_funcs(g))
        return NULL;

    if (g->rpoint >= 6 && (g->rstate == 4 || g->rstate == 9)) {
        int i;
        int result_sz, real_sz, src, dst;
        int slice_sz[5];

        for (i = 0; i < 5; i++)
            slice_sz[i] = g->rpoints[i+1] - g->rpoints[i];

        result_sz = gen_state_tell(g) + (slice_sz[1] + slice_sz[3]) * RECURSION_TIMES;
        if (chop) {
            real_sz = rnd(result_sz);
        } else {
            real_sz = result_sz;
        }

        if (gen_state_resize_buf(g, real_sz))
            return NULL;

        // slide slice 4 down to the end
        src = g->used - slice_sz[4];
        dst = result_sz - slice_sz[4];
        memcpy_upto(g->buf, dst, src, slice_sz[4], real_sz);

        // dupe slice 3 into place
        src -= slice_sz[3];
        dst -= slice_sz[3] * RECURSION_TIMES;
        for (i = RECURSION_TIMES - 1; i >= 0; i--)
            memcpy_upto(g->buf, dst + i * slice_sz[3], src, slice_sz[3], real_sz);

        // slide slice 2 into place
        src -= slice_sz[2];
        dst -= slice_sz[2];
        memcpy_upto(g->buf, dst, src, slice_sz[2], real_sz);

        // dupe slice 1 into place
        src -= slice_sz[1];
        dst -= slice_sz[1] * RECURSION_TIMES;
        for (i = RECURSION_TIMES - 1; i >= 1; i--) // the first dupe is already in place
            memcpy_upto(g->buf, dst + i * slice_sz[1], src, slice_sz[1], real_sz);

        // slice 0 already in place

        g->used = real_sz;
    } else if (chop) {
        g->used = rnd(g->used);
    }
    nr = PyBytes_FromStringAndSize(g->buf, g->used);
    free(g->buf);
    g->buf = NULL;
    return nr;
}

void
gen_state_dealloc(gen_state_t *g)
{
    int i, j;

    if (g->buf) {
        free(g->buf);
        //g->buf = NULL;
    }
    for (i = GRMOBJ(g->grammar)->max_id - 1; i >= 0; i--) {
        if (!g->sym_state[i].sym)
            continue;
        Py_CLEAR(g->sym_state[i].sym);
        Py_CLEAR(g->sym_state[i].descoped_instances);
        if (g->sym_state[i].scopes) {
            for (j = 0; j <= g->scope; j++)
                Py_CLEAR(g->sym_state[i].scopes[j]);
            free(g->sym_state[i].scopes);
            g->sym_state[i].scopes = NULL;
        }
        if (g->sym_state[i].tracked_references) {
            free(g->sym_state[i].tracked_references);
            g->sym_state[i].tracked_references = NULL;
        }
    }
    if (g->sym_state) {
        free(g->sym_state);
        //g->sym_state = NULL;
    }
    if (g->funcs) {
        for (i = 0; i < g->nfuncs; i++) {
            free(g->funcs[i].args);
            //g->funcs[i].args = NULL;
            Py_DECREF(g->funcs[i].sym);
        }
        free(g->funcs);
        //g->funcs = NULL;
    }
    Py_CLEAR(g->grammar);
}

