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
#define _CRT_RAND_S
#include <Python.h>
#include <stdlib.h>
#include <stdio.h>
#include "alf_grammar.h"
#include "rnd.h"

#ifdef _WIN32
double
rndl(double max)
{
    unsigned int r;
    if (rand_s(&r))
        PyErr_SetFromErrno(PyExc_WindowsError);
    return r * max / (UINT_MAX + 1.0);
}

double
rndl_inc(double max)
{
    unsigned int r;
    if (rand_s(&r))
        PyErr_SetFromErrno(PyExc_WindowsError);
    return r * max / UINT_MAX;
}
#endif

void
seedrnd(void)
{
#ifndef _WIN32
    unsigned int r;
    size_t g = 1;
    FILE *f;

    f = fopen("/dev/random", "rb");
    if (!f) {
        PyErr_SetFromErrno(PyExc_OSError);
        return;
    }
    while (g) {
        g -= fread(&r, sizeof(unsigned int), 1, f);
        if (ferror(f)) {
            PyErr_SetFromErrno(PyExc_OSError);
            break;
        }
    }
    fclose(f);
    srandom(r);
#endif

    ODBG("rnd() fingerprint: %d%d%d%d%d%d%d%d%d%d\n", rnd(10), rnd(10), rnd(10), rnd(10), rnd(10), rnd(10), rnd(10), rnd(10), rnd(10), rnd(10));
}

