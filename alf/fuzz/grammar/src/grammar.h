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
#ifndef __GRAMMAR_H__
#define __GRAMMAR_H__

typedef struct {
    PyObject_HEAD
    // Type-specific fields go here.
    int star_depth;
    int max_size;
    int max_depth;
    int last_depth_watermark;
    PyObject *root_sym;
    PyObject *root_obj;
    PyObject *txt_dict;
    PyObject *sym_dict;
    PyObject **sym_list;
    PyObject *pend_add_choice;
    int n_syms;
    int max_id;
} GrammarObject;

PyObject *_random_symbol(GrammarObject *self);
PyObject *generate_real(GrammarObject *self, PyObject *root);

#define GRMOBJ(x)       ((GrammarObject *)(x))
extern PyTypeObject GrammarType;

#endif

