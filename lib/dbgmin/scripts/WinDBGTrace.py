################################################################################
# Name        : WinDBGTrace
# Description : Get a stack trace from a timeout
# Author      : Tyson Smith
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
import optparse
import pykd
import re
import sys
import time

BLACKLIST_LIBS = ["verifier", "ntdll", "kernel32", "MSVCR", "GDI32", "KERNELBASE"]
LOG_DEBUG = False

class log(object):
    @staticmethod
    def info(msg, *args):
        print >> sys.stderr, msg % args
    @staticmethod
    def debug(msg, *args):
        if LOG_DEBUG:
            print >> sys.stderr, "DEBUG|" + msg % args

def get_current_stack():
    call_stack = []
    for line in pykd.dbgCommand("k").splitlines()[1:]:
        try:
            _, ret_addr, sym = line.split()
            _ = int(ret_addr, 16)
        except ValueError:
            continue
        call_stack.append(sym)
    return call_stack

def get_addr_list():
    addr_list = []
    addr_list.append(pykd.getContext().ip())
    for line in pykd.dbgCommand("k").splitlines()[1:]:
        skip = False
        try:
            _, ret_addr, sym = line.split()
            ret_addr = int(ret_addr, 16)
        except ValueError:
            continue
        for noise in BLACKLIST_LIBS:
            if sym.startswith(noise):
                skip = True
                break
        if skip:
            continue
        addr_list.append(ret_addr)
    addr_list.pop() # remove 0 from the list
    return addr_list

def get_thread_run_time(thread):
    # 0:xxx       0 days 0:00:00.000
    thread = thread.split()
    duration = int(thread[1]) * 86400 # days
    thread = thread[-1].split('.')
    duration += float("0.%s" % thread[-1])
    thread = thread[0].split(':')
    duration += int(thread[0]) * 3600 # hours
    duration += int(thread[1]) * 60 # minutes
    duration += int(thread[2]) # seconds
    return duration

def get_proc_run_time():
    #Debug session time: Tue Aug 21 16:27:31.971 2012 (UTC - 4:00)
    #System Uptime: 5 days 13:06:34.062
    #Process Uptime: 0 days 0:00:02.718
      #Kernel time: 0 days 0:00:00.000
      #User time: 0 days 0:00:00.000
    duration = 0
    for line in pykd.dbgCommand(".time").splitlines()[-2:]:
        line = line.strip().split()
        duration += int(line[2]) * 86400 # days
        line = line[-1].split('.')
        duration += float("0.%s" % line[-1])
        line = line[0].split(':')
        duration += int(line[0]) * 3600 # hours
        duration += int(line[1]) * 60 # minutes
        duration += int(line[2]) # seconds
    return duration

def get_thread_list():
    return pykd.dbgCommand("!runaway").splitlines()[2:]

def get_hung_thread():
    hung_thread = 0
    cur_max = 0
    for thread in get_thread_list():
        m = re.match(r"\s+([0-9a-f]+):[0-9a-f]+\s+[0-9]+\sdays\s", thread)
        if not m:
            continue
        run_time = get_thread_run_time(thread)
        if run_time > cur_max:
            hung_thread = int(m.group(1))
            cur_max = run_time
    return hung_thread

def set_thread(t_id):
    pykd.dbgCommand("~%d s" % t_id)

def set_bp(addr, bp_id, count):
    pykd.dbgCommand("ba%d e1 %x %d" % (bp_id, addr, count))

def is_complete():
    return pykd.dbgCommand(".lastevent").find("Exit process") != -1

def get_bp_hit():
    tmp_bp = pykd.dbgCommand(".lastevent")
    if tmp_bp.find("Hit breakpoint") != -1:
        return int(tmp_bp.splitlines()[0].split()[-1])
    return None

def find_next_sym(next_bp, prev_bp, timeout):
    iters = 100
    found_sym = False
    sample_time = 0

    set_bp(next_bp, 0, 1)
    set_bp(prev_bp, 1, iters)
    while not is_complete():
        pykd.go()
        curr_bp = get_bp_hit()
        target_time = get_proc_run_time()
        log.debug("target time %0.2f", target_time)
        if curr_bp == 1:
            if target_time >= timeout:
                break
            iter_duration = target_time - sample_time
            if iter_duration < 0.5: # optimization
                if iters < 25600:
                    iters *= 2
                    log.debug("iter duration: %0.2f, (x2) prev_bp iters: %d", iter_duration, iters)
            elif iter_duration >= 0.5 and iter_duration < 0.85: # optimization
                iters += 100
                log.debug("iter duration: %0.2f, (+100) prev_bp iters: %d", iter_duration, iters)
            set_bp(prev_bp, 1, iters)
        elif curr_bp == 0:
            found_sym = True
            break
        else:
            log.debug("break not triggered by breakpoint")
            if pykd.dbgCommand(".lastevent").find("(!!! second chance !!!)") != -1:
                raise RuntimeError("Expected Timeout found Access violation!")
        sample_time = target_time

    pykd.removeBp(1)
    pykd.removeBp(0)
    return found_sym

def filter_noise(call_stack):
    strip_count = 0
    for line in call_stack:
        for lib in BLACKLIST_LIBS:
            if line.startswith(lib):
                line = None
                break
        if line is not None and line.find("<") == -1 and line.find("[") == -1:
            break
        strip_count += 1
    return call_stack[strip_count:]

def main(timeout):
    run_time = time.time()
    log.debug("timeout: %0.2fs", timeout)
    log.debug("collect initial trace")
    set_thread(get_hung_thread())
    log.debug("init complete")

    addrs = get_addr_list()
    while len(addrs) > 1:
        log.debug("stack length: %d", len(addrs))
        if not find_next_sym(addrs[1], addrs[0], timeout) and not is_complete():
            log.debug("trace complete")
            break
        if get_proc_run_time() >= timeout:
            log.debug("trace timeout hit")
            break
        addrs.pop(0)
        if is_complete():
            log.info("target process has exited")
            addrs = list()

    log.info("*" * 60)
    if addrs:
        for line in filter_noise(get_current_stack()):
            log.info("STACK_FRAME:%s", line)
    else:
        log.info("Not a timeout!")
    log.info("*" * 60)
    log.info("----- STATS -----")
    log.info("DGB TIME: %0.2f", time.time()-run_time)
    log.info("PROC TIME: %0.2f", get_proc_run_time())
    log.info("THREAD TIME: %0.2f", get_thread_run_time(get_thread_list()[get_hung_thread()]))

if __name__ == '__main__':
    opter = optparse.OptionParser()
    opter.add_option("-t", "--timeout", dest="timeout", default=60, type="int",
        help="Amount of time in seconds to run target exe (default: 60)")
    opter.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
        help="display debug info")
    (opts, args) = opter.parse_args()
    LOG_DEBUG = opts.verbose
    main(opts.timeout)
