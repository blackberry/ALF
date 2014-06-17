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
#ifndef __GEN_STATE_H__
#define __GEN_STATE_H__

typedef struct {
    PyObject *sym;
    int count;
    PyObject *descoped_instances; // PySet (out of scope only)
    PyObject **scopes; // array of PySets
    int n_scoped_instances;
    int *tracked_references;
    int n_tracked_references;
    int tracking_start;
} _sym_state_t;

typedef struct {
    PyObject *sym;
    int nargs;
    int *args;
} _deferred_func_t;

typedef struct {
    int depth;
    int depth_watermark;
    int rstate;
    int rpoints[6];
    int rpoint;
    int tracking;
    PyObject *rsym;
    PyObject *grammar;
    PyObject *clean;
    _sym_state_t *sym_state;
    int max_size;
    char *buf;
    int used;
    int alloced;
    char printed_limit;
    char printed_depth;
    int in_function;
    int has_reference;
    int nfuncs;
    _deferred_func_t *funcs;
    int scope;
} gen_state_t;

int gen_state_init(gen_state_t *g, PyObject *grammar, int max_size);
int gen_state_write(gen_state_t *g, const char *s, unsigned int len);
int gen_state_defer_function(gen_state_t *g, PyObject *s, int nargs, int args[], int defer_depth);
int gen_state_tell(const gen_state_t *g);
int gen_state_backtrack(gen_state_t *g, int pos);
PyObject *gen_state_slice(const gen_state_t *g, int from, int to);
int gen_state_enter_function(gen_state_t *g);
int gen_state_leave_function(gen_state_t *g, int func_cookie);
char gen_state_hit_depth(gen_state_t *g);
char gen_state_hit_limit(gen_state_t *g);
PyObject *gen_state_expand(gen_state_t *g);
int gen_state_inc_star_depth(gen_state_t *g, PyObject *s);
int gen_state_get_star_depth(gen_state_t *g, PyObject *s);
int gen_state_dec_star_depth(gen_state_t *g, PyObject *s);
int gen_state_inc_scope(PyObject *unused, void *vg);
int gen_state_dec_scope(PyObject *unused, void *vg);
int gen_state_start_tracking_instance(gen_state_t *g, PyObject *s);
int gen_state_end_tracking_instance(gen_state_t *g, PyObject *s);
int gen_state_generate_scoped_instance(PyObject *s, void *vg);
int gen_state_mark_tracking_reference(gen_state_t *g, PyObject *s);
int gen_state_start_clean(gen_state_t *g, PyObject *s);
int gen_state_end_clean(gen_state_t *g, PyObject *s);
void gen_state_dealloc(gen_state_t *g);

#endif

