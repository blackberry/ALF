################################################################################
# Name   : CDB Wrapper
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
import logging as log
import os
import platform
import re
import signal
import subprocess
import tempfile
import time

from . import _common
if platform.system() == "Windows":
    import psutil
    import distutils.spawn

    POSSIBLE_PATHS = [
        os.environ['PATH'],
        os.path.join(os.environ['PROGRAMFILES(X86)'], 'Windows Kits', '8.x', 'Debuggers', 'x64'),
        os.path.join(os.environ['PROGRAMFILES(X86)'], 'Windows Kits', '8.x', 'Debuggers', 'x86'),
        os.path.join(_common.PATH_DBG),
    ]

    TOOL_CDB = distutils.spawn.find_executable('cdb.exe', os.pathsep.join(POSSIBLE_PATHS))

TIMEOUT_CHILD_EXIT_WAIT = 120
POLL_SLEEP = 0.05


def run_with_windbg(target_cmd, symbols=None, env=None, callback=None, callback_args=None,
                    pageheap=True, timeout=_common.DEFAULT_TIMEOUT, memory_limit=None,
                    idle_limit=None):
    """
    This function is similar to the :func:`run` function above,
    except the target is executed under control of the Windows
    Debugger (``WinDBG``).  Symbols may be specified manually,
    otherwise they are expected to be findable by the Windows
    Debugging API (usually in a ``.pdb`` file having the same basename
    as the target).

    :func:`run_with_windbg` returns a :class:`~alf.FuzzResult`
    instance.  If no crash was detected, the
    :attr:`~alf.FuzzResult.classification` member of the
    :class:`~alf.FuzzResult` will be
    :data:`~alf.debug.NOT_AN_EXCEPTION`.

    Classifications are derived from the `Microsoft !exploitable
    <http://msecdbg.codeplex.com/>`_ extension.

    Classifications: :data:`~alf.debug.EXCESS_MEMORY_USAGE`,
    :data:`~alf.debug.EXPLOITABLE`,
    :data:`~alf.debug.NOT_AN_EXCEPTION`,
    :data:`~alf.debug.PROBABLY_EXPLOITABLE`,
    :data:`~alf.debug.PROBABLY_NOT_EXPLOITABLE`,
    :data:`~alf.debug.TIMEOUT`, :data:`~alf.debug.UNKNOWN`.

    Availability: Windows.
    """
    target = os.path.basename(target_cmd[0])
    if pageheap and target not in _common._gflags_enabled:
        _common._set_gflags(target)
    res = _cdb_common(target_cmd=target_cmd, symbols=symbols, env=env, callback=callback,
                      callback_args=callback_args, timeout=timeout, memory_limit=memory_limit,
                      idle_limit=idle_limit)
    return res


def attach_with_windbg(target_pid, symbols=None, callback=None, callback_args=None,
                       timeout=_common.DEFAULT_TIMEOUT, memory_limit=None):
    """
    This function is similar to :func:`run_with_windbg`, except the
    target is expected to already be executing.  Symbols may be
    specified manually, otherwise they are expected to be findable by
    the Windows Debugging API (usually in a ``.pdb`` file having the
    same basename as the target).

    A callback is expected to be provided to interact with the target
    while the debugger is attached.  Once the callback returns, the
    debugger will be detached from the target.  This usually results
    in a :class:`~alf.FuzzResult` with classification
    :data:`~alf.debug.UNKNOWN` due to the breakpoint used to attach,
    unless the target crashes on its own.

    :func:`attach_with_windbg` returns a :class:`~alf.FuzzResult`
    instance.  If no crash was detected, the
    :attr:`~alf.FuzzResult.classification` member of the
    :class:`~alf.FuzzResult` will be :data:`~alf.debug.UNKNOWN` (as
    described in previous paragraph).

    Classifications are derived from the `Microsoft !exploitable
    <http://msecdbg.codeplex.com/>`_ extension.

    Classifications: :data:`~alf.debug.EXCESS_MEMORY_USAGE`,
    :data:`~alf.debug.EXPLOITABLE`,
    :data:`~alf.debug.NOT_AN_EXCEPTION`,
    :data:`~alf.debug.PROBABLY_EXPLOITABLE`,
    :data:`~alf.debug.PROBABLY_NOT_EXPLOITABLE`,
    :data:`~alf.debug.TIMEOUT`, :data:`~alf.debug.UNKNOWN`.

    Availability: Windows.
    """
    res = _cdb_common(target_pid=target_pid, symbols=symbols,
                      callback=callback, callback_args=callback_args,
                      timeout=timeout, memory_limit=memory_limit)
    return res[1]


def _cdb_common(target_pid=None, target_cmd=None, symbols=None, env=None, callback=None,
                callback_args=None, timeout=_common.DEFAULT_TIMEOUT, memory_limit=None,
                idle_limit=None):
    assert target_pid is not None or target_cmd is not None
    assert target_pid is None or target_cmd is None
    classification = None
    if env is None:
        env = dict(os.environ)
    env["LIBC_FATAL_STDERR_"] = "1"
    if symbols is not None:
        env["_NT_ALT_SYMBOL_PATH"] = symbols
    elif target_cmd:
        env["_NT_ALT_SYMBOL_PATH"] = os.path.abspath(os.path.dirname(target_cmd[0]))
    cdb_cmd = [TOOL_CDB, "-x", "-lines", "-y",
               "SRV*c:\\websymbols*http://msdl.microsoft.com/download/symbols",
               "-c", "!gflag;g;.lastevent;r;kb;!msec.exploitable -m;" \
               "!heap -s 0;!heap -h;.echo;q"] # keep -c last
    start_time = _common.prof_timer()
    with tempfile.TemporaryFile(mode="w+t") as f:
        if target_pid is not None:
            cdb_cmd[-1] += "d" # change final 'q' to 'qd'
            cdb_cmd += ["-p", "%d" % target_pid]
            p = subprocess.Popen(cdb_cmd, stderr=f, stdout=f, env=env,
                                 stdin=subprocess.PIPE, creationflags=_common.POPEN_FLAGS)
        else:
            p = subprocess.Popen(cdb_cmd + target_cmd, stderr=f, stdout=f, env=env,
                                 stdin=subprocess.PIPE, creationflags=_common.POPEN_FLAGS)
            ps = psutil.Process(p.pid)
            bn = os.path.basename(target_cmd[0])
            try:
                while (_common.prof_timer() - start_time) < timeout:
                    if p.poll() is not None:
                        raise psutil.NoSuchProcess(p.pid)
                    for kid in ps.get_children():
                        if kid.name != bn:
                            continue # guard against catching something other than
                                     # the target being launched by the debugger
                        assert target_pid is None, "debugger has multiple children"
                        target_pid = kid.pid
                    if target_pid is not None:
                        #log.debug("got child pid in %0.2fs", (_common.prof_timer() - start_time))
                        break
                    time.sleep(POLL_SLEEP)
                assert target_pid is not None, "Failed to get child pid"
            except psutil.NoSuchProcess:
                # this means CDB is already gone. so we can't possibly hit a timeout and we
                # won't use target_pid for anything anyways
                log.debug("target done before pid was found")
                target_pid = p.pid
        try:
            cb_res = _common._call_callback(callback, callback_args, target_pid)
            if cb_res == _common.CB_ERROR:
                raise RuntimeError("callback() returned error")
            if p.poll() is None and target_cmd is None:
                try:
                    p.send_signal(signal.CTRL_BREAK_EVENT)
                except WindowsError as e:
                    f.write("alf.debug.cdb: failed to send Ctrl+Break to debugger (%s)\n" % e)
                    log.warn("failed to send Ctrl+Break to debugger")
            target_mon = _common.TargetMonitor(target_pid, idle_limit=idle_limit,
                                               memory_limit=memory_limit, time_limit=timeout)
            while p.poll() is None:
                if target_mon.check_memory():
                    f.write("memory limit of %0.2f MB was exceeded\n" % (memory_limit/1048576))
                    classification = _common.EXCESS_MEMORY_USAGE
                    break
                if target_mon.check_idle():
                    break
                if target_mon.check_timeout():
                    classification = _common.TIMEOUT
                    break
                time.sleep(POLL_SLEEP)
        finally:
            if p.poll() is None:
                attempt = 0
                pid = target_pid
                while True:
                    if attempt == 1:
                        try:
                            p.send_signal(signal.CTRL_BREAK_EVENT)
                        except WindowsError as e:
                            f.write("alf.debug.cdb: failed to send Ctrl+Break to debugger (%s)\n"
                                    % e)
                            log.warn("failed to send Ctrl+Break to debugger")
                    else:
                        with open(os.devnull, "w") as fp:
                            subprocess.call(["taskkill", "/pid", str(pid), "/f", "/t"],
                                            stdout=fp, stderr=fp)
                    st = _common.prof_timer()
                    while p.poll() is None and \
                            (_common.prof_timer() - st) < TIMEOUT_CHILD_EXIT_WAIT:
                        time.sleep(POLL_SLEEP)
                    if p.poll() is not None:
                        break
                    if attempt == 0:
                        f.write("[%0.1f]alf.debug.cdb: failed to kill child pid %d, trying to "
                                "break into debugger instead\n" % (time.time(), pid))
                    elif attempt == 1:
                        f.write("[%0.1f]alf.debug.cdb: failed to break into debugger, trying to "
                                "kill parent pid %d instead\n" % (time.time(), pid))
                    pid = p.pid
                    attempt += 1
                    assert attempt <= 3, "Failed to kill the debugger twice !?!"
                assert attempt <= 1, "Shouldn't need to kill the debugger."
            exit_code = p.wait()
        f.seek(0, os.SEEK_SET)
        debug_log = f.read()
    backtrace = []
    m = re.search(r"^The call to LoadLibrary\((?P<lib>[a-z]+)\) failed, Win32 error 0n2",
                  debug_log, re.MULTILINE)
    if m is not None:
        raise RuntimeError("cdb failed on call to LoadLibrary(%s)" % m.group("lib"))
    debug_class = _common.NOT_AN_EXCEPTION
    if ("Last event: %x." % target_pid) in debug_log:
        backtrace, debug_class, exit_code = _common.process_exploitable_output(debug_log)
    if cb_res == _common.CB_HANG:
        classification = _common.TIMEOUT
    elif classification is None:
        if cb_res == _common.CB_FAIL:
            classification = _common.UNKNOWN
        else:
            classification = debug_class
    debug_log = _common._limit_output_length(debug_log)
    return _common.FuzzResult(classification, debug_log, backtrace, exit_code=exit_code)


def reduce_timeout_with_windbg(target_cmd, timeout=_common.DEFAULT_TIMEOUT, init_wait=None,
                               symbols=None, env=None, callback=None, callback_args=None):
    """
    Uses a super-sekrit algorithm to minimize a command which results
    in TIMEOUT classifications using nothing but WinDBG and raw nerve.
    It returns a :class:`FuzzResult`.

    Note: A timeout limit of less than 30 seconds may not produce
    accurate results.

    TODO: Add support for callback

    Availability: Windows.
    """
    if callback is not None:
        #TODO: Add support for callback
        raise RuntimeError("callback support not implemented")
    if timeout <= 0:
        raise ValueError("timeout must be greater than zero")

    if init_wait is None:
        init_wait = timeout / 4

    if env is None:
        env = dict(os.environ)
    env["LIBC_FATAL_STDERR_"] = "1"
    if symbols is not None:
        env["_NT_ALT_SYMBOL_PATH"] = symbols
    elif target_cmd:
        env["_NT_ALT_SYMBOL_PATH"] = os.path.abspath(os.path.dirname(target_cmd[0]))
    dbg_script = os.path.join(_common.PATH_DBG, "scripts", "WinDBGTrace.py")
    timeout_time = time.time() + init_wait
    cdb_cmd = [TOOL_CDB, "-x", "-y",
               "SRV*c:\\websymbols*http://msdl.microsoft.com/download/symbols",
               "-c", ".load pykd.pyd;g;!py %s -t %d -v;q" % (dbg_script, timeout)]
    gflags_args = _common._disable_gflags(target_cmd[0]) # we want to run as quickly as possible
    with tempfile.TemporaryFile(mode="w+t") as f:
        f.write("Timeout: %0.2f\n" % (timeout))
        if timeout < 30:
            f.write("A timeout less than 30 seconds may not produce accurate results\n")
        f.write("Init wait: %0.2f\n" % (init_wait))
        p = subprocess.Popen(cdb_cmd + target_cmd, stderr=f, stdout=f, env=env,
                             stdin=subprocess.PIPE, creationflags=_common.POPEN_FLAGS)
        kill_debugger = False
        while p.poll() is None:
            if time.time() > timeout_time:
                if not kill_debugger:
                    timeout_time = time.time() + (timeout * 5)
                    kill_debugger = True
                    try:
                        os.kill(p.pid, signal.CTRL_C_EVENT)
                    except OSError:
                        pass
                else:
                    with open(os.devnull, "w") as fp:
                        subprocess.call(["taskkill", "/pid", str(p.pid), "/f"],
                                        stdout=fp, stderr=fp)
                    p.wait()
            time.sleep(0.5) # no hurry, less cpu hogging is better

        f.seek(0, os.SEEK_SET)
        output = []
        for line in f.readlines():
            if line.strip() not in ["Breakpoint 0 hit", "Breakpoint 1 hit"]:
                output.append(line)
    if gflags_args is not None:
        _common._set_gflags(target_cmd[0], **gflags_args)
    output = ''.join(output)
    has_tb = output.find("Traceback (most recent call last):")
    if has_tb != -1:
        raise RuntimeError("CDB Python Failure\n%s\n%s" % ("-"*80, output[has_tb:]))
    call_stack = _common.process_exploitable_output(output)[0]
    if not call_stack:
        return _common.FuzzResult(text=output)
    return _common.FuzzResult(classification=_common.TIMEOUT, text=output, backtrace=call_stack)


def trace_memory_usage_with_windbg(target_cmd, init_sym, memory_limit,
                                   timeout=_common.DEFAULT_TIMEOUT, symbols=None, env=None,
                                   callback=None, callback_args=None):
    """
    This can be used to help pin point the call that causes the target
    application to exceed the defined memory limit.  It returns a
    :class:`FuzzResult`.

    init_sym is the symbol used for the initial breakpoint used to
    configure the run.  For example: <target>!main

    memory_limit is the memory limit in bytes that the application
    should not exceed.

    TODO: Add support for callback

    Availability: Windows.
    """

    if callback is not None: #TODO: Add support for callback
        raise RuntimeError("callback support not implemented")
    if not isinstance(init_sym, str):
        raise TypeError("init_sym must be of type str not %s" % type(init_sym).__name__)
    if not isinstance(memory_limit, int):
        raise TypeError("memory_limit be of type int not %s" % type(memory_limit).__name__)

    if env is None:
        env = dict(os.environ)
    env["LIBC_FATAL_STDERR_"] = "1"
    if symbols is not None:
        env["_NT_ALT_SYMBOL_PATH"] = symbols
    elif target_cmd:
        env["_NT_ALT_SYMBOL_PATH"] = os.path.abspath(os.path.dirname(target_cmd[0]))

    dbg_script = os.path.join(_common.PATH_DBG, "scripts", "WinDBGMemoryLimit.py")
    cdb_cmd = [TOOL_CDB, "-x", "-y",
               "SRV*c:\\websymbols*http://msdl.microsoft.com/download/symbols",
               "-c", ".load pykd.pyd;!py %s -l %d -s %s;q" % (dbg_script, memory_limit, init_sym)]

    gflags_args = _common._disable_gflags(target_cmd[0])
    with tempfile.TemporaryFile(mode="w+t") as f:
        p = subprocess.Popen(cdb_cmd + target_cmd, stderr=f, stdout=f, env=env,
                             stdin=subprocess.PIPE, creationflags=_common.POPEN_FLAGS)
        timeout_time = time.time() + timeout
        while p.poll() is None:
            if time.time() > timeout_time:
                with open(os.devnull, "w") as fp:
                    subprocess.call(["taskkill", "/pid", str(p.pid), "/f"], stdout=fp, stderr=fp)
                p.wait()
            time.sleep(0.5) # no hurry, less cpu hogging is better

        f.seek(0, os.SEEK_SET)
        output = []
        for line in f.readlines():
            if not line.strip().startswith("Breakpoint"):
                output.append(line)
    if gflags_args is not None:
        _common._set_gflags(target_cmd[0], **gflags_args)
    output = ''.join(output)
    has_tb = output.find("Traceback (most recent call last):")
    if has_tb != -1:
        raise RuntimeError("CDB Python Failure\n%s\n%s" % ("-"*80, output[has_tb:]))
    call_stack = _common.process_exploitable_output(output)[0]
    if not call_stack:
        return _common.FuzzResult(text=output)
    return _common.FuzzResult(classification=_common.EXCESS_MEMORY_USAGE,
                              text=output,
                              backtrace=call_stack)

