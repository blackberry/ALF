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
#ifndef __SYMBOL_H__
#define __SYMBOL_H__

typedef enum {
    SYM_TYPE_ABSTRACT = 0,
    SYM_TYPE_CONCAT,
    SYM_TYPE_CHOICE,
    SYM_TYPE_REGEX,
    SYM_TYPE_STAR,
    SYM_TYPE_TEXT,
    SYM_TYPE_FOREIGN,
    SYM_TYPE_REFERENCE,
    SYM_TYPE_SCOPED_REF,
    SYM_TYPE_RNDINT,
    SYM_TYPE_RNDFLT,
    SYM_TYPE_INCSCOPE,
    SYM_TYPE_DECSCOPE,
    SYM_TYPE_FUNCTION,
} gen_sym_type;

typedef struct {
    PyObject *charset;
    int min_count;
    int max_count;
} regex_pt_t;

typedef struct {
    PyObject_HEAD
    // Type-specific fields go here.
    char *name;
    int tracked;
    char clean;
    char recursive_clean;
    int line_no;
    int id;
    unsigned char type; // gen_sym_type
    char terminal;
    int (*_generate)(PyObject *, void *);
    union {
        PyObject *obj;
        struct {
            PyObject *grammar;
            PyObject *start_sym;
        } foreign;
        struct {
            PyObject **children;
            int n_children;
        } concat;
        struct {
            PyObject *f;
            PyObject *args;
        } func;
        struct {
            regex_pt_t *parts;
            int n_parts;
        } regex;
        struct {
            PyObject *child;
            double recommended_count;
        } star;
        struct {
            int a;
            int b;
        } rndint;
        struct {
            double a;
            double b;
        } rndflt;
    } data;
} SymbolObject;

int _generate(SymbolObject *s, void *g);
int define_text(SymbolObject *self, PyObject *text, int line_no);
PyObject *call_func_now(PyObject *s, const void *g, int nargs, const int args[]);

#define SYMOBJ(x)       ((SymbolObject *)(x))
extern PyTypeObject SymbolType;

#endif

