################################################################################
# Name        : WinDBGMemoryLimit
# Description : Get a stack trace from a process that exceeds a memory limit
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
import sys
import time

sys.path.append("..")
import psutil

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
    cur_max = 0.0
    for thread in get_thread_list():
        cur_thread = int(thread.split()[0].split(':')[0])
        if get_thread_run_time(thread) > cur_max:
            hung_thread = cur_thread
    return hung_thread

def set_thread(t_id):
    pykd.dbgCommand("~%d s" % t_id)

def sym_off_to_addr(sym_off):
    sym_off = sym_off.split("+")
    if len(sym_off) > 1:
        return pykd.getOffset(sym_off[0]) + int(sym_off[1], 16)
    else:
        return pykd.getOffset(sym_off[0])

def get_bp_hit():
    tmp_bp = pykd.dbgCommand(".lastevent")
    if tmp_bp.find("Hit breakpoint") != -1:
        return int(tmp_bp.splitlines()[0].split()[-1])
    return None

def get_mem_usage(pid):
    try:
        proc = psutil.Process(pid)
        tmp_val = proc.get_memory_info()[0]
    except psutil.NoSuchProcess:
        tmp_val = 0
    return tmp_val

def get_page_size():
    return int(pykd.dbgCommand("r $pagesize").split("=")[-1], 16)

def requested_mem_size():
    possible_bp_syms = ["calloc", "malloc", "realloc"]
    sym = None
    for line in pykd.dbgCommand("kb").splitlines()[1:]:
        try:
            _, _, arg0, arg1, _, sym = line.split()
            arg0 = int(arg0, 16)
            arg1 = int(arg1, 16)
            sym = sym.split("!")[1].strip()
        except (ValueError, IndexError):
            continue
        if sym in possible_bp_syms:
            break
        sym = None

    if sym == "calloc":
        ret_val = arg0 * arg1
    elif sym == "malloc":
        ret_val = arg0
    elif sym == "realloc":
        ret_val = arg1
    else:
        ret_val = 0
    return ret_val

def get_pid():
    return int(pykd.dbgCommand("|").split()[3], 16)

def main(init_sym, mem_limit, timeout):
    run_time = time.time()
    timeout = timeout + time.time()
    pykd.dbgCommand("bu %x" % sym_off_to_addr(init_sym))
    page_size = get_page_size()
    pykd.go()
    target_pid = get_pid()
    pykd.removeBp(get_bp_hit())
    pykd.dbgCommand("bm MSVCR*!malloc")
    pykd.dbgCommand("bm MSVCR*!realloc")
    pykd.dbgCommand("bm MSVCR*!calloc")
    log.debug("target pid: %d", target_pid)
    while time.time() < timeout:
        pykd.go()
        cur_mem = get_mem_usage(target_pid)
        if cur_mem >= mem_limit:
            log.info("missed request! current memory: %d", cur_mem)
            break
        req = requested_mem_size()
        if req == 0:
            log.info("unexpected break on: %s", get_current_stack()[0])
            continue
        if req > page_size:
            if req % page_size:
                page_req = page_size * ((req/page_size)+1)
            else:
                page_req = page_size * (req/page_size)
        else:
            page_req = page_size
        if cur_mem + page_req >= mem_limit:
            log.info("request will exceed limit, current: %d, request %d", cur_mem, req)
            break

    log.info("*" * 60)
    if time.time() < timeout:
        set_thread(get_hung_thread())
        call_stack = get_current_stack()
        if not call_stack:
            log.info("Unable to trace!")
        for line in call_stack:
            log.info("STACK_FRAME:%s" % line)
    else:
        log.info("Timeout!")
    log.info("*" * 60)
    log.info("----- STATS -----")
    log.info("MEMORY LIMIT: %d MB", mem_limit/0x100000)
    log.info("DGB TIME: %0.2f", time.time()-run_time)
    log.info("PROC TIME: %0.2f", get_proc_run_time())
    log.info("THREAD TIME: %0.2f", get_thread_run_time(get_thread_list()[get_hung_thread()]))

if __name__ == '__main__':
    opter = optparse.OptionParser()
    opter.add_option("-s", "--symbol", dest="symbol", type="str",
        help="Symbol for initial breakpoint (<target>!main)")
    opter.add_option("-l", "--limit", dest="limit", type="int",
        help="Memory limit in bytes")
    opter.add_option("-t", "--timeout", dest="timeout", type="int", default=60,
        help="Amount of time in seconds to run target exe (default: 60)")
    opter.add_option("-v", "--verbose", dest="verbose", action="store_true", default=False,
        help="display debug info")
    opts = opter.parse_args()[0]
    LOG_DEBUG = opts.verbose
    main(opts.symbol, opts.limit, opts.timeout)
