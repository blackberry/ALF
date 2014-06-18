set CC=cl
set PYROOT=C:\\Python27
set EXTRA_CFLAGS=

set PYTGT=..\\_alf_grammar.win32.pyd

set CFLAGS= /Zi /Ot /MT /W3 /GL /GS %EXTRA_CFLAGS%

%CC% %CFLAGS% /LD alf_grammar.c wchoice.c gen_state.c grammar.c rnd.c symbol.c /I. /I%PYROOT%\\include %PYROOT%\\Libs\\python27.lib /Fe%PYTGT%

