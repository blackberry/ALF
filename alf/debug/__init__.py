################################################################################
# Name   : ALF debugging library
# Author : Jesse Schwartzentruber & Tyson Smith
#
# Copyright 2014 BlackBerry Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
################################################################################
import platform

from . import _common
from . import _cdb
from . import _gdb
from . import _qemu

CB_PASS = _common.CB_PASS
CB_FAIL = _common.CB_FAIL
CB_HANG = _common.CB_HANG
CB_ERROR = _common.CB_ERROR

EXCESS_MEMORY_USAGE = _common.EXCESS_MEMORY_USAGE
EXPLOITABLE = _common.EXPLOITABLE
NOT_AN_EXCEPTION = _common.NOT_AN_EXCEPTION
PROBABLY_EXPLOITABLE = _common.PROBABLY_EXPLOITABLE
PROBABLY_NOT_EXPLOITABLE = _common.PROBABLY_NOT_EXPLOITABLE
TIMEOUT = _common.TIMEOUT
UNKNOWN = _common.UNKNOWN

DEFAULT_TIMEOUT = _common.DEFAULT_TIMEOUT

TargetPid = _common.TargetPid
FuzzResult = _common.FuzzResult
LSO = _common.LSO
TargetMonitor = _common.TargetMonitor
QEmuTarget = _qemu.QEmuTarget

run = _common.run
run_with_gdb = _gdb.run_with_gdb
symbolize_asan = _gdb.symbolize_asan
symbolize_valgrind = _gdb.symbolize_valgrind
run_with_windbg = _cdb.run_with_windbg
attach_with_windbg = _cdb.attach_with_windbg
reduce_timeout_with_windbg = _cdb.reduce_timeout_with_windbg
trace_memory_usage_with_windbg = _cdb.trace_memory_usage_with_windbg
lib_trim = _common.lib_trim

if platform.system() == "Windows":
    def set_memchecks(target, **kwargs):
        _cdb._set_gflags(target, **kwargs)
else:
    def set_memchecks(target, **kwargs):
        pass
