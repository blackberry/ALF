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
#include "alf_grammar.h"
#include "wchoice.h"
#include "rnd.h"

PyObject *
wchoice_append(WeightedChoiceObject *self, PyObject *args)
{
    void *newobj;
    PyObject *data;
    double weight;

    if (!PyArg_ParseTuple(args, "Od", &data, &weight))
        return NULL;
    PyObject_GC_UnTrack(self);
    self->count++;
    newobj = realloc(self->data, self->count * sizeof(struct _wchoice));
    if (!newobj) {
        self->count--;
        PyObject_GC_Track(self);
        PyErr_NoMemory();
        return NULL;
    }
    Py_INCREF(data);
    self->data = (struct _wchoice *)newobj;
    self->data[self->count-1].obj = data;
    self->data[self->count-1].wt = weight;
    self->total += weight;
    PyObject_GC_Track(self);
    Py_RETURN_NONE;
}

static int
wchoice_init(WeightedChoiceObject *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"iterable", NULL};
    PyObject *iterable = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|O", kwlist, &iterable))
        return -1;
    PyObject_GC_UnTrack(self);
    self->total = 0.0;
    self->count = 0;
    self->data = NULL;
    PyObject_GC_Track(self);
    if (iterable) {
        PyObject *res, *next, *iter = PyObject_GetIter(iterable);
        if (!iter)
            return -1;
        next = PyIter_Next(iter);
        while (next) {
            res = wchoice_append(self, next);
            Py_DECREF(next);
            if (!res) {
                Py_DECREF(iter);
                return -1;
            }
            Py_DECREF(res);
            next = PyIter_Next(iter);
        }
        Py_DECREF(iter);
        if (PyErr_Occurred())
            return -1;
    }
    return 0;
}

PyObject *
wchoice_choice(WeightedChoiceObject *self)
{
    double target_weight = rndl(self->total);
    int i;

    for (i = 0; i < self->count; i++) {
        target_weight -= self->data[i].wt;
        if (target_weight < 0.0) {
            Py_INCREF(self->data[i].obj);
            return self->data[i].obj;
        }
    }
    PyErr_Format(PyExc_RuntimeError, "Too much total weight? remainder is %0.2lf from %0.2lf total", target_weight, self->total);
    return NULL;
}

int
wchoice_len(WeightedChoiceObject *self)
{
    return self->count;
}

static void
wchoice_dealloc(WeightedChoiceObject *self)
{
    PyObject_GC_UnTrack(self);
    Py_TYPE(self)->tp_clear((PyObject *)self);
    if (self->data) {
        free(self->data);
        self->data = NULL;
    }
    Py_TYPE(self)->tp_free((PyObject *)self);
}

static int
wchoice_traverse(WeightedChoiceObject *self, visitproc visit, void *arg)
{
    int i;

    for (i = 0; i < self->count; i++)
        Py_VISIT(self->data[i].obj);
    return 0;
}

static int
wchoice_clear(WeightedChoiceObject *self)
{
    int i;

    for (i = 0; i < self->count; i++)
        Py_CLEAR(self->data[i].obj);
    self->count = 0;
    return 0;
}

static PyMethodDef WeightedChoice_methods[] = {
    {"append", (PyCFunction)wchoice_append, METH_VARARGS, NULL},
    {"choice", (PyCFunction)wchoice_choice, METH_NOARGS, NULL},
    {NULL} // Sentinel
};

PyTypeObject WeightedChoiceType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "_alf_grammar.WeightedChoice" ,     // tp_name
    sizeof(WeightedChoiceObject),       // tp_basicsize
    0,                                  // tp_itemsize
    (destructor)wchoice_dealloc,        // tp_dealloc
    0,                                  // tp_print
    0,                                  // tp_getattr
    0,                                  // tp_setattr
    0,                                  // tp_compare
    0,                                  // tp_repr
    0,                                  // tp_as_number
    0,                                  // tp_as_sequence
    0,                                  // tp_as_mapping
    0,                                  // tp_hash
    0,                                  // tp_call
    0,                                  // tp_str
    0,                                  // tp_getattro
    0,                                  // tp_setattro
    0,                                  // tp_as_buffer
    Py_TPFLAGS_DEFAULT|Py_TPFLAGS_HAVE_GC, // tp_flags
    "WeightedChoice objects",           // tp_doc
    (traverseproc)wchoice_traverse,     // tp_traverse
    (inquiry)wchoice_clear,             // tp_clear
    0,                                  // tp_richcompare
    0,                                  // tp_weaklistoffset
    0,                                  // tp_iter
    0,                                  // tp_iternext
    WeightedChoice_methods,             // tp_methods
    0,                                  // tp_members
    0,                                  // tp_getset
    0,                                  // tp_base
    0,                                  // tp_dict
    0,                                  // tp_descr_get
    0,                                  // tp_descr_set
    0,                                  // tp_dictoffset
    (initproc)wchoice_init,             // tp_init
    0,                                  // tp_alloc
    0,                                  // tp_new
};

