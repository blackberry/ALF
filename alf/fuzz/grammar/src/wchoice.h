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
#ifndef __WCHOICE_H__
#define __WCHOICE_H__

struct _wchoice {
    PyObject *obj;
    double wt;
};

typedef struct {
    PyObject_HEAD
    // Type-specific fields go here.
    double total;
    int count;
    struct _wchoice *data;
} WeightedChoiceObject;

extern PyTypeObject WeightedChoiceType;
PyObject *wchoice_append(WeightedChoiceObject *self, PyObject *args);
PyObject *wchoice_choice(WeightedChoiceObject *self);
int wchoice_len(WeightedChoiceObject *self);

#endif

