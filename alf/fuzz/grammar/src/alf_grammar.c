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
#include "gen_state.h"
#include "symbol.h"
#include "grammar.h"
#include "rnd.h"

static PyMethodDef AlfGrammarMethods[] = {
    {NULL} // Sentinel
};

unsigned int _grammar_debug = 0;

#if PY_MAJOR_VERSION >= 3
struct module_state {
    PyObject *error;
};
#define GETSTATE(m) ((struct module_state*)PyModule_GetState(m))

static int
alf_grammar_traverse(PyObject *m, visitproc visit, void *arg)
{
    Py_VISIT(GETSTATE(m)->error);
    return 0;
}

static int
alf_grammar_clear(PyObject *m)
{
    Py_CLEAR(GETSTATE(m)->error);
    return 0;
}

static struct PyModuleDef
moduledef = {
        PyModuleDef_HEAD_INIT,
        "_alf_grammar",
        NULL,
        sizeof(struct module_state),
        AlfGrammarMethods,
        NULL,
        alf_grammar_traverse,
        alf_grammar_clear,
        NULL
};

#define INITERROR return NULL

PyMODINIT_FUNC
PyInit__alf_grammar(void)
#else

#define INITERROR return

PyMODINIT_FUNC
init_alf_grammar(void)
#endif
{
    PyObject *m, *o;
    const char *dbg;

    dbg = getenv("GRAMMAR_DEBUG");
    if (dbg) {
        char *t;
        _grammar_debug = strtoul(dbg, &t, 0);
        if (t <= dbg || *t != '\0') {
            _grammar_debug = 0;
            PyErr_Format(PyExc_RuntimeError, "Unknown value for GRAMMAR_DEBUG, expecting int");
            INITERROR;
        }
    }

    seedrnd();

    GrammarType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&GrammarType) < 0)
        INITERROR;
    SymbolType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&SymbolType) < 0)
        INITERROR;
    WeightedChoiceType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&WeightedChoiceType) < 0)
        INITERROR;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&moduledef);
#else
    m = Py_InitModule("_alf_grammar", AlfGrammarMethods);
#endif

    if (m == NULL)
        INITERROR;

    o = (PyObject *)&GrammarType;
    Py_INCREF(o);
    PyModule_AddObject(m, "Grammar", o);
    o = (PyObject *)&SymbolType;
    Py_INCREF(o);
    PyModule_AddObject(m, "Symbol", o);
    o = (PyObject *)&WeightedChoiceType;
    Py_INCREF(o);
    PyModule_AddObject(m, "WeightedChoice", o);
#if PY_MAJOR_VERSION >= 3
    return m;
#endif
}

