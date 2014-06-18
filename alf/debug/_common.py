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
import hashlib
import os
import platform
import re
import signal
import sys
import tempfile
import time

try:
    sys.path.append(os.path.abspath(os.path.join(os.getcwd(), "lib")))
    import psutil
except (ImportError, NotImplementedError):
    class psutil(object):
        class Process(object):
            def __init__(self, pid):
                raise RuntimeError("psutil not available for this platform")
_platform = platform.system()

import subprocess

if _platform == "Windows":
    POPEN_FLAGS = subprocess.CREATE_NEW_PROCESS_GROUP
    prof_timer = time.clock
else:
    POPEN_FLAGS = 0
    prof_timer = time.time

PATH_DBG = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "lib", "dbgmin"))

CB_PASS  = 0
CB_FAIL  = 1
CB_HANG  = 2
CB_ERROR = 3

_delete_queue = []

DEFAULT_TIMEOUT = 60


class _Classification(object):
    """
    Internal class used for classification of FuzzResults
    """
    SUPPORTED_CLS = set(["EXCESS_MEMORY_USAGE", "EXPLOITABLE", "NOT_AN_EXCEPTION",
                         "PROBABLY_EXPLOITABLE", "PROBABLY_NOT_EXPLOITABLE", "TIMEOUT", "UNKNOWN"])
    def __init__(self, description):
        if isinstance(description, _Classification):
            description = description.description
        else:
            assert description in self.SUPPORTED_CLS, "Unsupported classification: %s" % description
        self.description = description
    def __str__(self):
        return self.description
    def __eq__(self, other):
        return str(self) == str(other)
    def __ne__(self, other):
        return str(self) != str(other)
    def __bool__(self):
        return self.description != "NOT_AN_EXCEPTION"


EXCESS_MEMORY_USAGE = _Classification("EXCESS_MEMORY_USAGE")
EXPLOITABLE = _Classification("EXPLOITABLE")
NOT_AN_EXCEPTION = _Classification("NOT_AN_EXCEPTION")
PROBABLY_EXPLOITABLE = _Classification("PROBABLY_EXPLOITABLE")
PROBABLY_NOT_EXPLOITABLE = _Classification("PROBABLY_NOT_EXPLOITABLE")
TIMEOUT = _Classification("TIMEOUT")
UNKNOWN = _Classification("UNKNOWN")


class TargetPid(object):
    """
    This class is a placeholder for the PID of the target process needed by
    a callback function in :func:`~run` or one of the similar functions
    provided in this module. If an instance of this class is given in the
    list of *callback_args*, it will be replaced with the pid (as an
    integer) before being passed to the callback.
    """
    pass


def run(target_cmd, stdin=None, callback=None, callback_args=None, env=None,
        timeout=DEFAULT_TIMEOUT, memory_limit=None, idle_limit=None):
    """
    This function runs the given target command in a sub-process, and
    returns the results. The *target_cmd* parameter should be a list
    of command line arguments, with the first argument being the target
    executable. The expected duration of the run is determined automatically.

    :func:`run` returns a :class:`FuzzResult`.

    Availability: Unix, Windows.
    """
    fail_class = NOT_AN_EXCEPTION
    if env is None:
        env = dict(os.environ)
    if _platform in ("Linux", "QNX"):
        if "ASAN_OPTIONS" not in env:
            # If the project does not set ASAN_OPTIONS use these as defaults
            env["ASAN_OPTIONS"] = "alloc_dealloc_mismatch=1 " \
                                  "allocator_may_return_null=1 " \
                                  "allow_user_poisoning=0 " \
                                  "check_initialization_order=1 " \
                                  "check_malloc_usable_size=0 " \
                                  "detect_stack_use_after_return=1 " \
                                  "disable_core=1 " \
                                  "exitcode=139 " \
                                  "handle_segv=1 " \
                                  "strict_init_order=1 " \
                                  "strict_memcmp=1"
        env["G_DEBUG"] = "gc-friendly" # https://developer.gnome.org/glib/unstable/glib-running.html
        env["G_SLICE"] = "always-malloc" # https://developer.gnome.org/glib/unstable/glib-running.html#G_SLICE
    env["LIBC_FATAL_STDERR_"] = "1"
    with tempfile.TemporaryFile(mode="w+t") as f:
        p = subprocess.Popen(target_cmd, stdin=stdin, stdout=f, stderr=f, env=env)
        try:
            cb_res = _call_callback(callback, callback_args, p.pid)
            if cb_res == CB_ERROR:
                raise RuntimeError("callback() returned error")
            target_mon = TargetMonitor(p.pid, idle_limit=idle_limit,
                                       memory_limit=memory_limit, time_limit=timeout)
            while p.poll() is None:
                if target_mon.check_memory():
                    fail_class = EXCESS_MEMORY_USAGE
                    break
                if target_mon.check_idle():
                    break
                if target_mon.check_timeout():
                    fail_class = TIMEOUT
                    break
                time.sleep(0.01)
        finally:
            if p.poll() is None:
                if _platform == "Windows":
                    with open(os.devnull, "w") as fp:
                        subprocess.call(["taskkill", "/pid", str(p.pid), "/f"], stdout=fp, stderr=fp)
                else:
                    os.kill(p.pid, signal.SIGKILL)
        exit_code = p.wait()
        f.seek(0, os.SEEK_SET)
        stdout = f.read()
    if exit_code != 0:
        if _platform in ("Linux", "QNX"):
            if exit_code < 0:
                sig = exit_code * -1
            elif exit_code > 128:
                sig = exit_code - 128
            else:
                sig = 0
            if sig not in (signal.SIGINT, signal.SIGKILL):
                fail_class = UNKNOWN
            elif exit_code in (126, 127):
                raise RuntimeError("Process exited with code %d.\n%s" % (exit_code, stdout))
        elif _platform == "Windows":
            fail_class = UNKNOWN
    if cb_res == CB_HANG:
        fail_class = TIMEOUT
    elif cb_res == CB_FAIL:
        fail_class = UNKNOWN
    return FuzzResult(classification=fail_class, text=stdout, exit_code=exit_code)


def _call_callback(callback, cb_args, pid):
    if callback is not None:
        if cb_args is None:
            cb_args = []
        else:
            cb_args = list(cb_args)
            for i, a in enumerate(cb_args):
                if isinstance(a, TargetPid):
                    cb_args[i] = pid
        return callback(*cb_args)
    else:
        return CB_PASS


def _limit_output_length(output):
    if len(output) > FuzzResult.MAX_TEXT:
        # truncate at the beginning to get the most info...
        truncmsg = "\n*** TRUNCATED, orig %d bytes ***\n" % len(output)
        output = "%s%s" % (output[-(FuzzResult.MAX_TEXT - len(truncmsg)):], truncmsg)
    return output


_RE_PROCESS_EXP = re.compile(r'''^CLASSIFICATION:
                                     (?P<classification>.*)                     |
                                 ^EXCEPTION_TYPE:
                                     (?P<exc_type>[A-Z_]+)                      |
                                 ^STACK_FRAME:
                                     ((?P<module>[^!]+)!)?
                                     (?P<symbol>[^+]+)
                                     (\+0x(?P<offset>[0-9a-f]+))?               |
                                 ^(?P<traceback>
                                   \s*Traceback\s\(most\srecent\scall\slast\):$             # traceback in exploitable
                                     \s+File\s"[^"]+?exploitable/exploitable\.py".*$\s+.*$  # first frame in exploitable.py
                                     (\s+File.*$\s+.*$)*                                    # one or more following frames
                                     \s*.*$)                                 |              # final line (exception desc)
                                 ^SHORT_DESCRIPTION:(?P<short_desc>[A-Za-z]+)   |
                                 ^Last\ event:\ .+?code\ (?P<exception>[0-9a-fA-F]+)
                              ''', re.MULTILINE|re.VERBOSE)


def process_exploitable_output(stdout):
    '''This function is used to process the output from CERT Exploitable and !exploitable'''
    classification = None
    exception = 0
    backtrace = []
    short_desc = None
    exc_type = None

    # Things noticed along the way.
    stack_cookie = None
    exploitable_exception = None

    # Look through the lines of debugger output for stuff.
    for m in _RE_PROCESS_EXP.finditer(stdout):
        if m.group('classification'):
            classification = _Classification(m.group('classification'))
        elif m.group('exc_type'):
            exc_type = m.group('exc_type')
        elif m.group('exception'):
            exception = int(m.group('exception'), 16)
            exploitable_exception = (exception in [0xC0000409])
        elif m.group('short_desc'):
            short_desc = m.group('short_desc')
        elif m.group('symbol'):
            module = m.group('module')
            symbol = m.group('symbol')
            offset = m.group('offset')
            if offset is not None:
                offset = int(offset, 16)
            backtrace.append(LSO((module, symbol, offset)))

            # A stack cookie is recognized by its symbol name.
            # A stack cookie causes an exception and a handler call.
            # A stack cookie exception is considered exploitable.
            stack_cookie = symbol in ['__report_gsfailure']
            if stack_cookie:
                # Erase the handler traceback.
                backtrace = []
        elif m.group('traceback'):
            raise RuntimeError("Crash in CERT triage tools:\n%s" % m.group('traceback'))
        else:
            # Unrecogniz(ed)(able) line from debugger
            pass

    if short_desc == "StackExhaustion":
        backtrace = backtrace[-10:]

    # Sometimes override the classification.
    if stack_cookie or exploitable_exception or \
            exc_type == "STATUS_STACK_BUFFER_OVERRUN":
        classification = EXPLOITABLE

    if exception >= 0x40000000 and exception < 0xC0200000 and \
            classification == NOT_AN_EXCEPTION:
        classification = UNKNOWN

    # these are false positive things, like ^C
    if exception in [0x40010005, 0x80000003]:
        classification = NOT_AN_EXCEPTION

    # Issues that indicate that the target may not be configured properly
    if exception in [0xC0000417]:
        # 0xC0000417: STATUS_INVALID_CRUNTIME_PARAMETER
        classification = UNKNOWN

    if classification is None:
        classification = NOT_AN_EXCEPTION

    return (backtrace, classification, exception)


class FuzzResult(object):
    """
    A notable result from a fuzzing iteration. This should be yielded from an
    execution of :meth:`Fuzzer.do_iteration`. It will be reported to the
    ALF central server at the next check-in interval, and accessible from the ALF
    website thereafter. The result will be associated with the mutation filename
    in the :meth:`Fuzzer.do_iteration` execution that yields this object.
    """
    MAX_TEXT = 1 * 1024 * 1024
    """Maximum string length allowed for the :attr:`text` attribute."""

    MAJOR_HASH_DEPTH = 4 # Do NOT change this unless you recalculate all hashs
    """Maximum stack depth for calculating the major hash."""

    def __init__(self, classification=NOT_AN_EXCEPTION, text="", backtrace=None, exit_code=0):
        self.classification = classification
        self.text = text
        self.backtrace = backtrace if backtrace is not None else []
        self.exit_code = exit_code

    @property
    def classification(self):
        """A classification constant as defined in :mod:`alf.debug`."""
        return self._classification
    @classification.setter
    def classification(self, value):
        self._classification = _Classification(value)

    @property
    def backtrace(self):
        """A list of :class:`LSO` objects representing a backtrace at the time of the crash.
           These are ordered by descending time (ie. most recent is first in the list).
           It is an error for this to be empty if :attr:`~alf.FuzzResult.classification` is
           anything other than :data:`~alf.debug.NOT_AN_EXCEPTION`."""
        return self._backtrace
    @backtrace.setter
    def backtrace(self, value):
        self._backtrace = list(value)

    @property
    def exit_code(self):
        """This is the exit code from the target process."""
        return self._exit_code
    @exit_code.setter
    def exit_code(self, exit_code):
        if not isinstance(exit_code, int) and hasattr(__builtins__, "long") and not isinstance(exit_code, long):
            raise TypeError("exit_code must be an int, got %s" % type(exit_code))
        self._exit_code = exit_code

    @property
    def text(self):
        """
        A freeform string to describe the result. It is suggested this include
        the standard output and error streams from the target. Cannot exceed
        :attr:`MAX_TEXT` in length.
        """
        return self._text
    @text.setter
    def text(self, value):
        if not isinstance(value, str):
            raise TypeError("Expecting text to be a str, got a %s" % type(value))
        self._text = _limit_output_length(value)

    def _calc_hash(self, max_depth, use_offset):
        hasher = hashlib.sha224()
        for s in self.backtrace[:max_depth]:
            sym = s.get_str(include_offset=False)
            if not sym:
                sym = "Unknown"
            else:
                sym = sym.lower()
            hasher.update(sym)
            if use_offset:
                # to be consistant make sure we are dealing with an int not a str that could be
                #   base 10 or 16 or 0X or 0x...
                offset = s.off if s.off is not None else 0
                assert isinstance(offset, int) or (hasattr(__builtins__, "long") and isinstance(offset, long)), \
                    "Offset is %s should be int. Value: %s" % (type(offset), offset)
                hasher.update(str(offset))
        # sha224 is 224bits or 28 bytes or 56 hex chars
        return hasher.hexdigest().upper()

    @property
    def major(self):
        """This is the major hash of this result based on the backtrace for grouping."""
        return self._calc_hash(self.MAJOR_HASH_DEPTH, False)

    @property
    def minor(self):
        """This is the minor hash of this result based on the backtrace for grouping."""
        return self._calc_hash(len(self.backtrace), True)


class FuzzDeletion(object):
    """
    A file or folder created by a fuzzing iteration which should be cleaned up safely. This
    should be yielded from an execution of :meth:`Fuzzer.do_iteration`. The
    file or folder will be deleted in a safe manner after :meth:`Fuzzer.do_iteration`
    returns.
    """
    def __init__(self, path):
        if not isinstance(path, str):
            raise TypeError("Expecting path to be a str, got a %s" % type(path))

        self.path = path
        """The path of the file or folder to be deleted."""


class LSO(object):
    """
    Representation of a resolved address in an executable image.
    *lso* is a tuple containing the library name, symbol name, and offset.
    The interpretation of offset is given in the table below.

    ===========  ========  ===================
    Library      Symbol    Offset
    ===========  ========  ===================
    (any value)  not None  relative to symbol
    not None     None      relative to library
    None         None      absolute address
    ===========  ========  ===================

    This is the primary way that symbols are represented internally by ALF,
    which allows for consistent handling and formatting.

    Call stacks and backtraces are represented as lists of LSOs, organized head-first.
    (Note that :py:meth:`list.pop` assumes tail-first by default. Use
    ``pop(0)``.)
    """
    def __init__(self, lso):
        self.lib = lso[0]
        """Library"""
        self.sym = lso[1]
        """Symbol"""
        self.off = lso[2]
        """Offset"""
        if self.off is not None:
            self.off = int(self.off)
    def get_str(self, include_offset=True):
        """Return a string representation of the address in the form
        'library!symbol+offset' if *include_offset* is True, otherwise in the form
        'library!symbol'."""
        if self.lib and self.sym:
            result = "%s!%s" % (self.lib, self.sym)
        elif self.lib:
            result = self.lib
        elif self.sym:
            result = self.sym
        else: # missing both lib and sym
            result = "Unknown"
        if include_offset and self.off is not None:
            result = "%s+0x%x" % (result, self.off)
        return result
    def __eq__(self, other):
        return (self.lib, self.sym, self.off) == (other.lib, other.sym, other.off)
    def __ne__(self, other):
        return (self.lib, self.sym, self.off) != (other.lib, other.sym, other.off)
    def __le__(self, other):
        return (self.lib, self.sym, self.off) <= (other.lib, other.sym, other.off)
    def __ge__(self, other):
        return (self.lib, self.sym, self.off) >= (other.lib, other.sym, other.off)
    def __lt__(self, other):
        return (self.lib, self.sym, self.off) < (other.lib, other.sym, other.off)
    def __gt__(self, other):
        return (self.lib, self.sym, self.off) > (other.lib, other.sym, other.off)
    def __str__(self):
        return self.get_str(True)
    def __repr__(self):
        return str(self)


def _get_delete_path():
    try:
        return _delete_queue.pop(0)
    except IndexError:
        return None


def delete(path):
    """
    Delete files/folders in a safer manner than using :func:`os.remove` or
    :func:`shutil.rmtree` directly.
    """
    assert isinstance(path, str)
    _delete_queue.append(path)


def lib_trim(back_trace, noise, trim_bottom=False):
    """
    This can be used to remove unwanted noise from a list of :class:`LSO` objects representing a
    backtrace. It will return a list of :class:`LSO` objects.

    back_trace is a list of :class:`LSO` objects representing a backtrace.

    noise is a list of strings that represent the library of entries that will be removed from 
    back_trace.

    trim_bottom will trim noise symbols off the bottom of the call stack.
    """
    assert isinstance(back_trace, list)
    assert isinstance(noise, list)
    if trim_bottom:
        back_trace.reverse()
    while True:
        for entry in noise:
            if not back_trace:
                return []
            if back_trace[0].lib == entry:
                back_trace.pop(0)
                break
        else:
            break
    if trim_bottom:
        back_trace.reverse()
    return back_trace


class TargetMonitor(object):
    IDLE_CHECK = 0.1 # seconds
    IDLE_THRESHOLD = 3.0 # percent
    MEMORY_CHECK = 0.1
    TIMEOUT_CHECK = 0.1
    def __init__(self, pid, idle_limit=None, memory_limit=None, time_limit=None):
        self.limit = {"idle":idle_limit,
                      "memory":memory_limit,
                      "time":time_limit}
        self.check = {"idle":0,
                      "memory":0,
                      "time":0}
        self.idle_start = None
        try:
            if isinstance(pid, psutil.Process):
                self.ps = pid
            else:
                self.ps = psutil.Process(pid)
            self.ps.get_cpu_percent(interval=0)
        except psutil.NoSuchProcess:
            self.ps = None

    def check_idle(self):
        now = prof_timer()
        if self.limit["idle"] and self.ps and (now - self.check["idle"]) > self.IDLE_CHECK:
            self.check["idle"] = now
            try:
                cpu_time = self.ps.get_cpu_percent(interval=0) # target cpu usage
                for child in self.ps.get_children(recursive=True):
                    try:
                        c_cpu = child.get_cpu_percent(interval=0)
                        if c_cpu > cpu_time:
                            cpu_time = c_cpu
                    except psutil.NoSuchProcess:
                        pass
            except psutil.NoSuchProcess:
                return False
            if cpu_time < self.IDLE_THRESHOLD:
                if self.idle_start and (now - self.idle_start) > self.limit["idle"]:
                    return True
                if self.idle_start is None:
                    self.idle_start = now
            else:
                self.idle_start = None
        return False

    def check_memory(self):
        now = prof_timer()
        if self.limit["memory"] and self.ps and (now - self.check["memory"]) > self.MEMORY_CHECK:
            self.check["memory"] = now
            try:
                target_mem = self.ps.get_memory_info()[0] # target memory usage
                for child in self.ps.get_children(recursive=True):
                    try:
                        target_mem += child.get_memory_info()[0]
                    except psutil.NoSuchProcess:
                        pass
            except psutil.NoSuchProcess:
                target_mem = 0
            if target_mem > self.limit["memory"]:
                return True
        return False

    def check_timeout(self):
        now = time.time()
        if self.limit["time"] and self.ps and (now - self.check["time"]) > self.TIMEOUT_CHECK:
            self.check["time"] = now
            try:
                target_time = self.ps.create_time()
            except psutil.NoSuchProcess:
                return False
            if time.time() - target_time > self.limit["time"]:
                return True
        return False


if _platform == "Windows":
    TOOL_GFLAGS = os.path.join(PATH_DBG, "gflags.exe")
    _gflags_enabled = dict()
    _gflags_args = {"backwards":False, "full":True, "leaks":False, "no_sync":False,
                    "notraces":False, "protect":True, "unaligned":True}
    def _set_gflags(target, **kwargs):
        """
        Enable page heap with gflags

        backwards: Places the zone of reserved virtual memory at the beginning of an allocation,
        rather than at the end. As a result, the debugger traps overruns at the beginning of the
        buffer, instead of those at the end of the buffer. Valid only with the /full parameter.

        full: Turns on full page heap verification for the process. Full page heap verification
        places a zone of reserved virtual memory at the end of each allocation.

        leaks: Checks for heap leaks when a process ends. The /leaks parameter disables
        full page heap. When /leaks is used, the /full parameter and parameters that modify
        the /full parameter, such as /backwards, are ignored, and GFlags performs standard
        page heap verification with a leak check.

        no_sync: Checks for unsynchronized access. This parameter causes a break if it detects that
        a heap created with the HEAP_NO_SERIALIZE flag is accessed by different threads.
        Do not use this flag to debug a program that includes a customized heap manager.
        Functions that synchronize heap access cause the page heap verifier to report
        synchronization faults that do not exist.

        notraces: Specifies that run-time stack traces are not saved. This option improves
        performance slightly, but it makes debugging much more difficult. This parameter is valid,
        but its use is not recommended.

        protect: Protects heap internal structures. This test is used to detect random heap
        corruptions. It can make execution significantly slower.

        unaligned: Place allocation at the end of the page so off-by-one issues trigger an AV.
        NOTE: Some programs make assumptions about 8-byte alignment and they stop working
        correctly with the /unaligned parameter.

        More info: http://msdn.microsoft.com/en-us/library/windows/hardware/ff549566
        """
        target = os.path.basename(target)
        if target in _gflags_enabled and _gflags_enabled[target] == kwargs:
            return # no changes necessary

        command = [TOOL_GFLAGS, "/p", "/enable", target]
        if not kwargs:
            kwargs = _gflags_args
        for arg, value in kwargs.items():
            if arg not in _gflags_args:
                raise RuntimeError("Invalid argument: %s" % arg)
            if not isinstance(value, bool):
                raise RuntimeError("Invalid type for argument '%s', should be " \
                                   "bool not %s" % (arg, type(value).__name__))
            if value:
                command.append("/%s" % arg)

        with open(os.devnull, "w") as nul:
            assert(subprocess.Popen(command, stderr=nul, stdout=nul).wait() == 0)
        _gflags_enabled[target] = kwargs


    def _disable_gflags(target):
        # disable page heap with gflags
        target = os.path.basename(target)
        command = [TOOL_GFLAGS, "/p", "/disable", target]
        with open(os.devnull, "w") as nul:
            assert(subprocess.Popen(command, stderr=nul, stdout=nul).wait() == 0)
        return _gflags_enabled.pop(target, None)

