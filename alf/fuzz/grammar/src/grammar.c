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
#include "grammar.h"
#include "gen_state.h"
#include "symbol.h"
#include "wchoice.h"
#include "rnd.h"

static PyObject *new_symbol(GrammarObject *self, const char *name, int line_no);
static PyObject *Grammar_getitem(GrammarObject *self, Py_ssize_t i);

static int
Grammar_init(GrammarObject *self, PyObject *args, PyObject *kwds)
{
    PyObject *o;
    static char *kwlist[] = {NULL};

    PyObject_GC_UnTrack(self);
    self->sym_list = NULL;
    self->n_syms = 0;
    self->star_depth = 5;
    self->max_depth = 0;
    self->last_depth_watermark = 0;
    self->max_size = -1;
    self->max_id = 0;
    self->root_obj = NULL;
    if (!PyArg_ParseTupleAndKeywords(args, kwds, "", kwlist))
        return -1;
    self->sym_dict = PyDict_New();
    if (!self->sym_dict)
        return -1;
    o = new_symbol(self, "[scope enter]", 0);
    if (!o)
        goto fail;
    if (PyDict_SetItemString(self->sym_dict, "{", o)) {
        Py_DECREF(o);
        goto fail;
    }
    SYMOBJ(o)->type = SYM_TYPE_INCSCOPE;
    SYMOBJ(o)->_generate = gen_state_inc_scope;
    Py_DECREF(o);
    o = new_symbol(self, "[scope exit]", 0);
    if (!o)
        goto fail;
    if (PyDict_SetItemString(self->sym_dict, "}", o)) {
        Py_DECREF(o);
        goto fail;
    }
    SYMOBJ(o)->type = SYM_TYPE_DECSCOPE;
    SYMOBJ(o)->_generate = gen_state_dec_scope;
    Py_DECREF(o);
    self->txt_dict = PyDict_New();
    if (!self->txt_dict)
        goto fail;
    ODBGN(D_REF, "++ grammar\n");
    PyObject_GC_Track(self);
    return 0;
fail:
    Py_DECREF(self->sym_dict);
    return -1;
}

static void
Grammar_dealloc(GrammarObject *self)
{
    ODBGN(D_REF, "-- grammar\n");
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_clear((PyObject *)self);
    if (self->sym_list) {
        free(self->sym_list);
        self->sym_list = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static PyObject *
Grammar_subscript(GrammarObject *self, PyObject *key)
{
    PyObject *res;
    res = PyDict_GetItem(self->sym_dict, key);
    if (res == NULL && PyLong_Check(key)) {
        return Grammar_getitem(self, PyLong_AsSsize_t(key));
    } else if (res == NULL) {
        PyErr_SetObject(PyExc_KeyError, key);
        return NULL;
    } else {
        Py_INCREF(res);
        return res;
    }
}

PyObject *
_random_symbol(GrammarObject *self)
{
    PyObject *r;
    do {
        r = self->sym_list[rnd(self->n_syms)];
    } while (SYMOBJ(r)->recursive_clean || SYMOBJ(r)->clean || SYMOBJ(r)->tracked);
    return r;
}

PyObject *
generate_real(GrammarObject *self, PyObject *root)
{
    gen_state_t g;
    PyObject *result;
#if PY_MAJOR_VERSION >= 3
    PyObject *nres;
#endif

    if (gen_state_init(&g, (PyObject *)self, self->max_size))
        return NULL;
    if (_generate(SYMOBJ(root), &g)) {
        gen_state_dealloc(&g);
        return NULL;
    }

    result = gen_state_expand(&g);
    self->last_depth_watermark = g.depth_watermark;
    gen_state_dealloc(&g);
#if PY_MAJOR_VERSION >= 3
    if (!result)
        return NULL;
    nres = PyUnicode_FromEncodedObject(result, "utf-8", "strict");
    Py_DECREF(result);
    return nres;
#else
    return result;
#endif
}

static PyObject *
generate(GrammarObject *self, PyObject *args)
{
    PyObject *root;

    if (!PyArg_ParseTuple(args, "O", &root))
        return NULL;

    if (Py_TYPE(root) == &SymbolType)
        return generate_real(self, root);
    if (root == self->root_obj && Py_TYPE(self->root_sym) == &SymbolType)
        return generate_real(self, self->root_sym);
    self->root_obj = NULL;
    self->root_sym = PyDict_GetItem(self->sym_dict, root);
    if (!self->root_sym) {
        PyErr_Format(PyExc_KeyError, "Start symbol not defined: %s", PyBytes_AsString(root));
        return NULL;
    }
    self->root_obj = root;
    return generate_real(self, self->root_sym);
}

static PyObject *
sanity_check(GrammarObject *self) // check for no abstracts, all concats/choices have children
{
    int i;
    SymbolObject *sym;

    for (i = 0; i < self->n_syms; i++) {
        sym = SYMOBJ(self->sym_list[i]);
        switch (sym->type) {
            case SYM_TYPE_ABSTRACT:
                PyErr_Format(PyExc_RuntimeError, "A symbol was used but not defined: %s (L%d)", sym->name, sym->line_no);
                return NULL;
            case SYM_TYPE_CHOICE:
                if (wchoice_len((WeightedChoiceObject *)sym->data.obj) == 0) {
                    PyErr_Format(PyExc_RuntimeError, "Choice symbol with no children: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                break;
            case SYM_TYPE_CONCAT:
                if (sym->data.concat.n_children == 0) {
                    PyErr_Format(PyExc_RuntimeError, "Concatenation symbol with no children: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                break;
            case SYM_TYPE_FOREIGN:
                if (sym->data.foreign.grammar == NULL) {
                    PyErr_Format(PyExc_RuntimeError, "Foreign grammar symbol without a grammar: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                if (sym->data.foreign.start_sym == NULL) {
                    PyErr_Format(PyExc_RuntimeError, "Foreign grammar symbol without a start symbol: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                break;
            case SYM_TYPE_FUNCTION:
                if (sym->data.func.f == NULL) {
                    PyErr_Format(PyExc_RuntimeError, "Function symbol without a function: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                if (!PyCallable_Check(sym->data.func.f)) {
                    PyErr_Format(PyExc_RuntimeError, "Function symbol callback has wrong type: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                if (sym->data.func.args == NULL) {
                    PyErr_Format(PyExc_RuntimeError, "Function symbol without args: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                if (!PySequence_Check(sym->data.func.args)) {
                    PyErr_Format(PyExc_RuntimeError, "Function symbol with non-sequence args: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                break;
            case SYM_TYPE_REGEX:
                if (sym->data.regex.n_parts == 0) {
                    PyErr_Format(PyExc_RuntimeError, "Regex symbol without data: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                break;
            case SYM_TYPE_STAR:
                if (sym->data.star.child == NULL) {
                    PyErr_Format(PyExc_RuntimeError, "Star symbol without data: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                break;
            case SYM_TYPE_TEXT:
                if (sym->data.obj == NULL) {
                    PyErr_Format(PyExc_RuntimeError, "Text symbol without data: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                break;
            case SYM_TYPE_SCOPED_REF:
            case SYM_TYPE_REFERENCE:
                if (sym->data.obj == NULL) {
                    PyErr_Format(PyExc_RuntimeError, "Reference symbol without a tracked symbol: %s (L%d)", sym->name, sym->line_no);
                    return NULL;
                }
                if (!SYMOBJ(sym->data.obj)->tracked) {
                    PyErr_Format(PyExc_RuntimeError, "Reference symbol refers to a non-tracked symbol: %s (L%d) -> %s (L%d)", sym->name, sym->line_no,
                            SYMOBJ(sym->data.obj)->name, SYMOBJ(sym->data.obj)->line_no);
                    return NULL;
                }
                break;
            default:
                PyErr_Format(PyExc_RuntimeError, "A symbol was defined but type is not handled: %s (L%d) type %d", sym->name, sym->line_no, sym->type);
                return NULL;
        }
    }
    Py_RETURN_NONE;
}

static PyObject *
new_symbol(GrammarObject *self, const char *name, int line_no)
{
    PyObject *res, *args;

    args = Py_BuildValue("(isi)", self->max_id, name, line_no);
    if (!args)
        return NULL;
    res = PyObject_CallObject((PyObject *)&SymbolType, args);
    Py_DECREF(args);
    if (res)
        self->max_id++;
    return res;
}

static PyObject *
new_symbol_py(GrammarObject *self, PyObject *args)
{
    const char *name;
    int line_no;

    if (!PyArg_ParseTuple(args, "si", &name, &line_no))
        return NULL;
    return new_symbol(self, name, line_no);
}

static PyObject *
name_to_symbol(GrammarObject *self, PyObject *args)
{
    const char *name;
    int line_no;
    PyObject *out;
    void *newobj;

    if (!PyArg_ParseTuple(args, "si", &name, &line_no))
        return NULL;
    out = PyDict_GetItemString(self->sym_dict, name);
    if (out) {
        Py_INCREF(out);
        return out;
    }
    out = new_symbol(self, name, line_no);
    if (!out)
        return NULL;
    self->max_id--; // don't reserve the id just yet...
    PyObject_GC_UnTrack(self);
    self->n_syms++;
    newobj = realloc(self->sym_list, self->n_syms * sizeof(PyObject *));
    if (!newobj) {
        Py_DECREF(out);
        PyErr_NoMemory();
        self->n_syms--;
        PyObject_GC_Track(self);
        return NULL;
    }
    self->sym_list = (PyObject **)newobj;
    self->sym_list[self->n_syms-1] = out;
    PyObject_GC_Track(self);
    Py_INCREF(out); // hold onto an extra reference for sym_list
    if (PyDict_SetItemString(self->sym_dict, name, out)) {
        Py_DECREF(out);
        return NULL;
    }
    self->max_id++;
    return out;
}

static PyObject *
text_to_symbol(GrammarObject *self, PyObject *args)
{
    PyObject *text;
    int line_no;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "Si", &text, &line_no)) {
        PyObject *unicode;
        PyErr_Clear();
        if (!PyArg_ParseTuple(args, "Ui", &unicode, &line_no))
            return NULL;
        text = PyUnicode_AsEncodedString(unicode, "utf-8", "strict");
        if (!text)
            return NULL;
    } else {
        Py_INCREF(text); // only needed for symmetry w/ the unicode case
    }
    out = PyDict_GetItem(self->txt_dict, text);
    if (out) {
        Py_INCREF(out);
        Py_DECREF(text);
        return out;
    }
    out = new_symbol(self, "[text]", line_no);
    if (!out) {
        Py_DECREF(text);
        return NULL;
    }
    self->max_id--; // don't reserve the id just yet...
    if (PyDict_SetItem(self->txt_dict, text, out)) {
        Py_DECREF(out);
        Py_DECREF(text);
        return NULL;
    }
    if (define_text(SYMOBJ(out), text, line_no)) {
        Py_DECREF(out);
        Py_DECREF(text);
        return NULL;
    }
    Py_DECREF(text);
    self->max_id++;
    return out;
}

static Py_ssize_t
Grammar_length(GrammarObject *self)
{
    return self->n_syms;
}

static PyObject *
Grammar_getitem(GrammarObject *self, Py_ssize_t i)
{
    if (i >= 0 && i < self->n_syms) {
        PyObject *ret = self->sym_list[i];
        if (!ret) {
            PyErr_Format(PyExc_RuntimeError, "got NULL for %d-th symbol in grammar?", i);
            return NULL;
        }
        Py_INCREF(ret);
        return ret;
    }
    PyErr_Format(PyExc_IndexError, "index out of range");
    return NULL;
}

static int
Grammar_traverse(GrammarObject *self, visitproc visit, void *arg)
{
    int i;
    Py_VISIT(self->sym_dict);
    Py_VISIT(self->txt_dict);
    for (i = 0; i < self->n_syms; i++)
        Py_VISIT(self->sym_list[i]);
    return 0;
}

static int
Grammar_clear(GrammarObject *self)
{
    int i;
    Py_CLEAR(self->sym_dict);
    Py_CLEAR(self->txt_dict);
    for (i = 0; i < self->n_syms; i++)
        Py_CLEAR(self->sym_list[i]);
    self->n_syms = 0;
    return 0;
}

static PyMethodDef Grammar_methods[] = {
    {"generate", (PyCFunction)generate, METH_VARARGS, NULL},
    {"sanity_check", (PyCFunction)sanity_check, METH_NOARGS, NULL},
    {"name_to_symbol", (PyCFunction)name_to_symbol, METH_VARARGS, NULL},
    {"text_to_symbol", (PyCFunction)text_to_symbol, METH_VARARGS, NULL},
    {"new_symbol", (PyCFunction)new_symbol_py, METH_VARARGS, NULL},
    {NULL} // Sentinel
};

static PyMemberDef Grammar_members[] = {
    {"star_depth", T_INT, offsetof(GrammarObject, star_depth), 0, "Depth factor for * symbols."},
    {"max_size", T_INT, offsetof(GrammarObject, max_size), 0, "Maximum generation size. Results may be slightly larger."},
    {"max_depth", T_INT, offsetof(GrammarObject, max_depth), 0, "Maximum recursion depth."},
    {"last_depth_watermark", T_INT, offsetof(GrammarObject, last_depth_watermark), READONLY, "Recursion depth watermark of the last call to generate()."},
    {NULL} // Sentinel
};

static PyMappingMethods Grammar_mapping_methods = {
    0,                              // mp_length
    (binaryfunc)Grammar_subscript,  // mp_subscript
    0,                              // mp_ass_subscript
};

static PySequenceMethods Grammar_sq_methods = {
    (lenfunc)Grammar_length,            // sq_length
    0,                                  // sq_concat
    0,                                  // sq_repeat
    (ssizeargfunc)Grammar_getitem,      // sq_item
    0,                                  // sq_ass_item
    0,                                  // sq_contains
    0,                                  // sq_inplace_concat
    0,                                  // sq_inplace_repeat
};

PyTypeObject GrammarType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_alf_grammar.Grammar",             // tp_name
    sizeof(GrammarObject),              // tp_basicsize
    0,                                  // tp_itemsize
    (destructor)Grammar_dealloc,        // tp_dealloc
    0,                                  // tp_print
    0,                                  // tp_getattr
    0,                                  // tp_setattr
    0,                                  // tp_compare
    0,                                  // tp_repr
    0,                                  // tp_as_number
    &Grammar_sq_methods,                // tp_as_sequence
    &Grammar_mapping_methods,           // tp_as_mapping
    0,                                  // tp_hash
    0,                                  // tp_call
    0,                                  // tp_str
    0,                                  // tp_getattro
    0,                                  // tp_setattro
    0,                                  // tp_as_buffer
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC, // tp_flags
    "Grammar objects",                  // tp_doc
    (traverseproc)Grammar_traverse,     // tp_traverse
    (inquiry)Grammar_clear,             // tp_clear
    0,                                  // tp_richcompare
    0,                                  // tp_weaklistoffset
    0,                                  // tp_iter
    0,                                  // tp_iternext
    Grammar_methods,                    // tp_methods
    Grammar_members,                    // tp_members
    0,                                  // tp_getset
    0,                                  // tp_base
    0,                                  // tp_dict
    0,                                  // tp_descr_get
    0,                                  // tp_descr_set
    0,                                  // tp_dictoffset
    (initproc)Grammar_init,             // tp_init
    0,                                  // tp_alloc
    0,                                  // tp_new
};

