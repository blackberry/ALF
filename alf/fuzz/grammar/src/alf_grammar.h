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
#ifndef __ALF_GRAMMAR_H__
#define __ALF_GRAMMAR_H__

#define RECURSION_TIMES 7

extern unsigned int _grammar_debug;

#define D_GEN                   (1<<0)  // generation = 1
#define D_PRS                   (1<<1)  // parsing = 2
#define D_LMT                   (1<<2)  // limits = 4
#define D_REF                   (1<<3)  // references = 8
#define D_TRK                   (1<<4)  // tracking = 16
#define D_CLN                   (1<<5)  // tracking = 32
#define D_TRM                   (1<<6)  // termination = 64

#define ISDBG(lvl)              (_grammar_debug & (lvl))
#define DBG(fmt, ...)           {if(_grammar_debug){int __dbg_i;fprintf(stderr, "%08X ",gen_state_tell(g));for(__dbg_i=0;__dbg_i<g->depth;__dbg_i++)fprintf(stderr,"  ");fprintf(stderr,fmt,##__VA_ARGS__);}}
#define DBGN(lvl, fmt, ...)     {if(_grammar_debug&(lvl)){int __dbg_i;fprintf(stderr, "%08X ",gen_state_tell(g));for(__dbg_i=0;__dbg_i<g->depth;__dbg_i++)fprintf(stderr,"  ");fprintf(stderr,fmt,##__VA_ARGS__);}}
#define ODBG(fmt, ...)          {if(_grammar_debug) fprintf(stderr, "         " fmt, ##__VA_ARGS__);}
#define ODBGN(lvl, fmt, ...)    {if(_grammar_debug & (lvl)) fprintf(stderr, "         " fmt, ##__VA_ARGS__);}
#define PDBG(fmt, ...)          {if(_grammar_debug) fprintf(stderr, fmt, ##__VA_ARGS__);}
#define PDBGN(lvl, fmt, ...)    {if(_grammar_debug & (lvl)) fprintf(stderr, fmt, ##__VA_ARGS__);}

#define STRBUF_SZ       (1024*1024)

#endif

