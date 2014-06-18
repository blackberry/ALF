################################################################################
# Name   : GDB Wrapper
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
import distutils.spawn
import os
import platform
import re
import signal
import tempfile
import time

from . import _common

CLOSE_FDS = True
if platform.system() in ["Linux", "Darwin"]:
    TOOL_GDB = distutils.spawn.find_executable('gdb', os.pathsep.join([os.environ['PATH'], _common.PATH_DBG]))
    if platform.system() == "Linux":
        TOOL_GDB_NTO = os.path.join(_common.PATH_DBG, "linux_x64-gdb-ntoarm")
        TOOL_KDSRV = os.path.join(_common.PATH_DBG, "linux_x64-kdserver")
    else:
        TOOL_GDB_NTO = None
        TOOL_KDSRV = None
elif platform.system() == "QNX":
    TOOL_GDB = {"x86": os.path.join(_common.PATH_DBG, "ntox86-gdb"),
                "armle": os.path.join(_common.PATH_DBG, "ntoarm-gdb"),
               }[platform.processor()]
    TOOL_GDB_NTO = TOOL_GDB
    TOOL_KDSRV = None
    assert os.access(TOOL_GDB, os.X_OK), "%s is not executable" % TOOL_GDB
elif platform.system() == "Windows":
    TOOL_GDB = distutils.spawn.find_executable('gdb.exe', os.pathsep.join([os.environ['PATH'], _common.PATH_DBG]))
    TOOL_GDB_NTO = os.path.join(_common.PATH_DBG, "gdb-ntoarm.exe")
    TOOL_KDSRV = os.path.join(_common.PATH_DBG, "kdserver.exe")
    CLOSE_FDS = False
GDB_CMDS = os.path.join(os.path.abspath(os.path.dirname(__file__)), "cmds.gdb")


# child sometimes doesn't die on SIGTERM in QNX
# wait this length of time before sending another SIGTERM, and finally SIGKILL
SLAY_TIMEOUT = 10


def _send_signal(signal, *args):
    for pid in args:
        if pid:
            os.kill(pid, signal)
            break


def _trim_disassembly(stdout):
    if not stdout:
        return stdout
    start_loc = stdout.find("Dump of assembler code")
    end_loc = stdout.find("End of assembler dump.", start_loc)
    if start_loc == -1 or end_loc == -1:
        return "%s\nError trimming assembler dump. start_loc = %d, end_loc = %d" % (stdout,
                                                                                    start_loc,
                                                                                    end_loc)
    try:
        a, b = stdout[start_loc:end_loc].split("\n=>")
    except ValueError:
        return "%s\nError trimming assembler dump. Could not find '=>'" % (stdout)
    a = a.splitlines()
    start_loc += len(a.pop(0))
    return "%s\n%s\n=>%s\n%s" % (stdout[:start_loc],
                                 "\n".join(a[-15:]),
                                 "\n".join(b.splitlines()[:15]),
                                 stdout[end_loc:])


def _gdb_cmd(target_exe, solib_search=None, run=True):
    return [TOOL_GDB, "-nx", "-x", GDB_CMDS] + \
           [i for sl in [("-ex", x) for x in
            _gdb_cmd_gen(run=run, target=target_exe, solib_search=solib_search)] for i in sl] + \
           ["-return-child-result", "-batch", "--args"]


def run_with_gdb(target_cmd, symbols=None, solib_search=None, env=None, callback=None,
                 callback_args=None, timeout=_common.DEFAULT_TIMEOUT, memory_limit=None,
                 idle_limit=None):
    """
    This function is similar to the :func:`run` function above,
    except the target is executed under control of the GNU Debugger.
    Symbols may be specified manually, otherwise they are expected
    to be findable by GDB (usually included in the target itself).

    :func:`run_with_gdb` returns a :class:`~alf.FuzzResult` instance.
    If no crash was detected, the :attr:`~alf.FuzzResult.classification`
    member of the :class:`~alf.FuzzResult` will be
    :data:`~alf.debug.NOT_AN_EXCEPTION`.

    Classifications: :data:`~alf.debug.NOT_AN_EXCEPTION`,
    :data:`~alf.debug.TIMEOUT`, :data:`~alf.debug.UNKNOWN`.

    Availability: Unix, Windows.
    """
    classification = None
    cpid = None
    if platform.system() == "Windows":
        _common._set_gflags(target_cmd[0])
    if platform.system() == "QNX":
        if not os.path.isfile("libc.so.3"):
            if not os.path.isfile("/root/symbols/x86/lib/libc.so.3.sym"):
                raise RuntimeError("Cannot find /root/symbols/x86/lib/libc.so.3.sym")
            os.symlink("/root/symbols/x86/lib/libc.so.3.sym", "libc.so.3")
    fd, temp_fn = tempfile.mkstemp(prefix="gdb", suffix=".log", dir=".")
    os.close(fd)
    nul = open(os.devnull, "w+")
    try:
        with open(temp_fn, "w+") as f:
            if env is None:
                env = dict(os.environ)
            env["LIBC_FATAL_STDERR_"] = "1"
            p = _common.subprocess.Popen(_gdb_cmd(target_cmd[0], solib_search) + target_cmd,
                close_fds=CLOSE_FDS, stdout=f, stderr=f, stdin=nul,
                creationflags=_common.POPEN_FLAGS, env=env)
            try:
                with open(temp_fn) as fr:
                    while p.poll() is None:
                        line = fr.readline()
                        m = re.match(r"^\*\s+1\s+Thread\s+\w+\s+\(LWP\s+(?P<pid>[0-9]+)\)", line)
                        if m is None:
                            m = re.match(r"^\*\s+1\s+(pid|process|Thread)\s+(?P<pid>[0-9]+)", line)
                        if m:
                            cpid = int(m.group("pid"))
                            break
                cb_res = _common._call_callback(callback, callback_args, p.pid)
                if cb_res == _common.CB_ERROR:
                    raise RuntimeError("callback() returned error")
                target_mon = _common.TargetMonitor(cpid, idle_limit=idle_limit,
                                                   memory_limit=memory_limit, time_limit=timeout)
                while p.poll() is None:
                    if target_mon.check_memory():
                        classification = _common.EXCESS_MEMORY_USAGE
                        break
                    if target_mon.check_idle():
                        break
                    if target_mon.check_timeout():
                        classification = _common.TIMEOUT
                        break
                    time.sleep(0.01)
            finally:
                while p.poll() is None:
                    try:
                        if platform.system() == "QNX":
                            attempt = -1
                            sigs = [signal.SIGTERM, signal.SIGKILL]
                            while p.poll() is None:
                                attempt += 1
                                assert attempt < len(sigs), "Failed to kill child process"
                                _send_signal(sigs[attempt], cpid, p.pid)
                                kill_time = _common.prof_timer()
                                while _common.prof_timer() - kill_time < SLAY_TIMEOUT:
                                    if p.poll() is not None:
                                        break
                                    time.sleep(0.25)
                        elif platform.system() == "Windows":
                            _send_signal(signal.CTRL_BREAK_EVENT, cpid, p.pid)
                        else:
                            _send_signal(signal.SIGTERM, cpid, p.pid)
                    except OSError:
                        pass
                exit_code = p.wait()
            f.seek(0, os.SEEK_SET)
            stdout = f.read()
    finally:
        _common.delete(temp_fn)
        nul.close()
    m = re.search(r"Traceback \(\D+\):.+Python command:", stdout, re.DOTALL)
    if m:
        tb = m.group(0)
        tb = tb[:tb.rfind("\n")]
        if not tb.endswith("No threads running"):
            raise RuntimeError("GDB Python Failure\n\n%s" % tb)
        else:
            return _common.FuzzResult(_common.NOT_AN_EXCEPTION, stdout)
    backtrace, debug_classification = _process_gdb_output(stdout)
    if cb_res == _common.CB_HANG:
        classification = _common.TIMEOUT
    elif classification is None:
        if cb_res == _common.CB_FAIL:
            classification = _common.UNKNOWN
        else:
            classification = debug_classification
    stdout = _trim_disassembly(stdout)
    stdout = _common._limit_output_length(stdout)
    return _common.FuzzResult(classification, stdout, backtrace, exit_code)


def _symbolize(target, output, tool, exp_opt):
    fd, tmp_log = tempfile.mkstemp(prefix="%s_log" % tool, suffix=".txt", dir=".")
    try:
        os.write(fd, output)
    finally:
        os.close(fd)
    try:
        result = _common.run([TOOL_GDB, "-batch", "-nx",
                                        "-ex", "set python print-stack full",
                                        "-ex", "py import exploitable",
                                        "-ex", "exploitable -m %s %s" % (exp_opt, tmp_log),
                                        "-ex", "quit", target], timeout=180)
    finally:
        _common.delete(tmp_log)
    if result.classification == _common.TIMEOUT:
        raise RuntimeError("Timed out while processing %s output:\n%s" % (tool, output))
    result.backtrace, result.classification = _process_gdb_output(result.text)
    result.text = _common._limit_output_length(result.text)
    if result.classification == _common.NOT_AN_EXCEPTION:
        raise RuntimeError("Failed to process %s output:\n%s" % (tool, output))
    return result


def symbolize_valgrind(target, valgrind_output):
    """
    Creates a :class:`~alf.FuzzResult` with classification by analyzing the log
    generated by Valgrind/Memcheck.
    """
    return _symbolize(target, valgrind_output, "valgrind", "-vg")


def symbolize_asan(target, asan_output):
    """
    Creates a :class:`~alf.FuzzResult` with classification by analyzing the log
    generated by AddressSanitizer.

    The result.text includes asan_output, but symbolized if possible.
    """
    return _symbolize(target, asan_output, "asan", "-a")


def _gdb_core_debug(symbols, ucore=None, kcore=None, remote=None, solib_search=None):
    assert TOOL_GDB_NTO, "GDB targetting NTO not available for this platform"
    if kcore:
        assert TOOL_KDSRV, "kdserver not available for this platform"
    assert len([x for x in [ucore, kcore, remote] if x is not None]) == 1, "Must specify exactly one core file"
    with tempfile.TemporaryFile() as f:
        gdb_cmd = [TOOL_GDB_NTO, "-nx", "-x", GDB_CMDS, symbols]
        if ucore is not None:
            gdb_cmd.append(ucore)
        gdb = _common.subprocess.Popen(gdb_cmd, stdout=f, stderr=f, stdin=_common.subprocess.PIPE)
        if kcore is not None:
            gdb.stdin.write("target remote |%s %s\n" % (TOOL_KDSRV, kcore.replace("\\", "\\\\")))
        elif remote is not None:
            gdb.stdin.write("target remote %s\n" % remote)
        core = ucore or kcore
        for c in _gdb_cmd_gen(core=core, solib_search=solib_search, detach=not core):
            gdb.stdin.write("%s\n" % c)
        gdb_wait_st = _common.prof_timer()
        while gdb.poll() is None and (_common.prof_timer() - gdb_wait_st) < 20:
            time.sleep(0.1)
        if gdb.poll() is None:
            gdb.terminate()
        gdb.wait()
        f.seek(0)
        gdb_out = f.read()
    trim = gdb_out.find(r'$1 = "TRIM"')
    if trim != -1:
        gdb_out = "\n".join([l for l in gdb_out[:trim].splitlines()[:-1] if not l.startswith("#0")] +
                             gdb_out[trim:].splitlines()[1:] + [""])
    bt, cls = _process_gdb_output(gdb_out)
    gdb_out = _trim_disassembly(gdb_out)
    return _common.FuzzResult(cls, gdb_out, bt)


def _gdb_cmd_gen(core=False, run=False, use_rcheck=False,
                 solib_search=None, target=None, detach=False, follow_child=False):
    # static cmds, sequence definitions, or conditional cmds (if, while, etc.) must go in cmds.gdb
    if follow_child:
        yield "set follow-fork-mode child"
    if run and use_rcheck:
        yield "set environment LD_PRELOAD librcheck.so"
        # Suppress prints from librcheck
        yield "set environment MALLOC_FILE /dev/null"
        # memory tracing on start. If memory tracing is disabled, errors can't report allocation/deallocation backtraces for memory chunk involved in error condition.
        yield "set environment MALLOC_START_TRACING 0"
        # Start control thread, and allows the IDE to send commands to the application (can't use if process forks).
        yield "set environment MALLOC_CTHREAD 0"
        # Check for out of bounds errors on every allocation/deallocation.
        yield "set environment MALLOC_CKBOUNDS 0"
        # Check strings and memory functions for errors.
        yield "set environment MALLOC_CKACCESS 0"
        # Check free and alloc functions for errors.
        yield "set environment MALLOC_CKALLOC 0"
        # Set error action behavior, 1-abort, 2 - exit (no core), 3 - dump core
        yield "set environment MALLOC_ACTION 0"
        # Enable dumping leaks on exit
        yield "set environment MALLOC_DUMP_LEAKS 0" # TODO: This causes a trace back when mem leaks are caught
        # Set to 0 to disable optimization. The default is 32
        yield "set environment MALLOC_USE_CACHE 0"
        # Check the allocator chain integrity on every allocation/deallocation (very expensive).
        yield "set environment MALLOC_CKCHAIN 0"
    if solib_search:
        yield "set solib-search-path %s" % solib_search
    if core:
        # put in a trim marker, because GDB runs "backtrace 1 full" when loading a core file
        yield "print \"TRIM\""
        yield "info program"
        yield "monitor kprintf"
    elif run:
        yield "set environment ASAN_OPTIONS abort_on_error=1 handle_segv=0 strict_memcmp=0 alloc_dealloc_mismatch=0 check_malloc_usable_size=0"
        yield "start"
        # need the pid to be able to kill it
        yield "info threads"
        # continue running
        yield "continue"
        yield "symbol-file"
        if target is None:
            raise RuntimeError("Missing target")
        yield "symbol-file %s" % target
        yield "sharedlibrary"
    yield "info proc mappings" # Linux only?
    yield "info meminfo" # QNX, does it work on core files?
    yield "info threads"
    # try to load symbols for any shared libs that were dynamically loaded
    yield "shared"
    # print library info so we know if symbols are missing
    yield "info sharedlibrary"
    yield "backtrace full"
    yield "exploitable -m"
    yield "info locals"
    yield "info registers"
    yield "disassemble"
    if detach:
        yield "detach"
    if platform.system() == "Windows":
        if core:
            yield "quit $_exitcode"
        else:
            yield "init-if-undefined $_exitcode = -1"
            # this doesn't work in the hang case
            #yield "while $_exitcode == -1"
            #yield "continue"
            #yield "end"
            yield "quit $_exitcode"
    else:
        yield "quit_with_code"


_RE_GDB_OUTPUT = re.compile(r"""(?x) # verbose
                                ^(It\ stopped\ with|Program\ received)\ signal
                                     \ (?P<signame>SIG[A-Z]+),                 |
                                ^Program\ terminated\ with\ signal
                                     \ (?P<signum>[0-9]+),                     |
                                ^\s+(?P<mapstart>0x[A-Fa-f0-9]+)\s+
                                    (?P<mapend>0x[A-Fa-f0-9]+)\s+
                                    (?P<mapsize>0x[A-Fa-f0-9]+)\s+
                                    (?P<mapoffset>0x[A-Fa-f0-9]+)\s+
                                    (?P<mapimage>.*)$                          |
                                ^\#[0-9]+\s+(?P<addr1>0x[A-Fa-f0-9]+)?\s*
                                           <(?P<image1>[A-Za-z0-9_\.-]+)!
                                            (?P<symbol1>[A-Za-z0-9_:]+)(\([^\+]+\))?\+?
                                            (?P<offset1>[0-9]+)?>\s+\(         |
                                ^\#[0-9]+\s+(?P<addr2>0x[A-Fa-f0-9]+)\s+\(\)   |
                                ^\#[0-9]+\s+(?P<addr3>0x[A-Fa-f0-9]+)?(\s+in)?\s+
                                            (?P<symbol3>[A-Za-z0-9_:?]+)\s+\(.*?\)\s+
                                (from|at)\s+(?P<image3>[A-Za-z0-9_\./-]+):?
                                            (?P<offset3>[0-9]+)?$              |
                                ^\#[0-9]+\s+(?P<addr4>0x[A-Fa-f0-9]+)?(\s+in)?\s+
                                            (?P<symbol4>[A-Za-z0-9_:?]+)""", re.MULTILINE)


def _process_gdb_output(stdout):
    # try parsing for CERT exploitable output first
    backtrace, classification, _ = _common.process_exploitable_output(stdout)
    if classification != _common.NOT_AN_EXCEPTION or backtrace:
        return (backtrace, classification)
    # CERT exploitable failed...
    classification = _common.NOT_AN_EXCEPTION
    backtrace = []
    maps = {}
    for m in _RE_GDB_OUTPUT.finditer(stdout):
        sig = None
        if m.group("signame"):
            sig = m.group("signame")
        elif m.group("signum"):
            sig = int(m.group("signum"))
        elif m.group("symbol1"):
            addr = m.group("addr1")
            image = m.group("image1")
            symbol = m.group("symbol1")
            offset = m.group("offset1")
        elif m.group("addr2"):
            addr = m.group("addr2")
            image = symbol = offset = None
        elif m.group("symbol3"):
            addr = m.group("addr3")
            image = m.group("image3")
            symbol = m.group("symbol3")
            offset = m.group("offset3")
            if symbol == "??":
                symbol = "Unknown"
            if image:
                image = os.path.basename(image)
        elif m.group("symbol4"):
            addr = m.group("addr4")
            symbol = m.group("symbol4")
            image = offset = None
        elif m.group("mapstart"):
            maps[(int(m.group("mapstart"), 16), int(m.group("mapend"), 16))] = m.group("mapimage")
            continue
        if sig is not None:
            if sig in [8, "SIGFPE"]:
                classification = _common.PROBABLY_NOT_EXPLOITABLE
            elif sig not in [2, "SIGINT"]:
                classification = _common.UNKNOWN
        else:
            if addr is not None:
                addr = int(addr, 16)
            if offset is not None:
                offset = int(offset)
            backtrace.append((addr, image, symbol, offset))
    real_bt = []
    for (addr, image, symbol, offset) in backtrace:
        if addr is not None:
            # try to find a map matching this address
            for (m_start, m_end), m_image in maps.items():
                if (addr >= m_start) and (addr < m_end):
                    rel_addr = addr - m_start
                    #log.debug("got rel_addr of %s+0x%08X for symbol %s", m_image, rel_addr, symbol)
                    if image is None:
                        image = os.path.basename(m_image)
                    if offset is None:
                        offset = rel_addr
                    break
        real_bt.append(_common.LSO((image, symbol, offset)))
    return (real_bt, classification)

