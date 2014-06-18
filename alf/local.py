################################################################################
# Name   : ALF Development Kit (ADK) Local Client
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
import argparse
import importlib
import logging as log
import os
import pickle
import random
import sys
import _thread
import threading
import time
import traceback

from alf import _registered, Fuzzer, rm_full_dir, delete
from .debug._common import FuzzResult, _get_delete_path
from .reduce import _reduce, reducers


def print_progress(start_time, iterno, results):
    "period print helper"
    elapsed = time.time() - start_time
    if elapsed > 0:
        rate = 1.0 * iterno / elapsed
    else:
        rate = 0.0
    log.info("%-20d %-10.2f %d", iterno, rate, results)


def do_deletes():
    while True:
        f = _get_delete_path()
        if f is None:
            break
        try:
            if os.path.isfile(f):
                os.remove(f)
            elif os.path.isdir(f):
                rm_full_dir(f)
        except OSError:
            log.error("Failed to delete: %s", f)


def main(proj_name, project_inst, run_folder, template_fn, iters, aggr_min, aggr_max,
         keep, timeout, write_pickle, reduce, reduce_n):
    "main loop"
    ext = os.path.splitext(os.path.basename(template_fn))[1]
    results = 0
    iterno = 0
    is_replay = (iters == 1 and aggr_min == 0 and aggr_max == 0)
    log.info("Running project %s for %d iteration(s).", proj_name, iters)
    log.info("Results will be written to %s", run_folder)
    log.info("Iteration timeout: %r", timeout)
    log.info("Ctrl+C to quit")
    log.info("%-20s %-10s %s", "Iterations", "Rate", "Failures")
    start_time = time.time()
    print_time = start_time
    done = False
    if timeout is not None:
        timeout_event = threading.Event()
        timeout_continue = threading.Event()
        class TimeoutThread(threading.Thread):
            def run(self):
                while not done:
                    if timeout_event.wait(timeout) is False:
                        # dump thread stacks and exit
                        log.error("Iteration timeout occurred!")
                        for thread_id, stack in sys._current_frames().items():
                            if thread_id == self.ident:
                                continue
                            log.error("Thread: %d", thread_id)
                            traceback.print_stack(stack)
                            log.error("")
                        _thread.interrupt_main()
                        return
                    timeout_event.clear()
                    timeout_continue.set()
        tout_tid = TimeoutThread()
        tout_tid.start()
    try:
        while not iters or iterno < iters:
            printed = False
            # create mutation fn
            if is_replay:
                mutation_fn = os.path.basename(template_fn)
            else:
                mutation_fn = "mutation_%08X%s" % (iterno, ext)
            # do an iteration
            iter_had_result = False
            cls = ""
            result = project_inst.do_iteration(mutation_fn, random.randint(aggr_max, aggr_min))

            if result is not None:
                if not isinstance(result, FuzzResult):
                    raise TypeError("Expecting FuzzResult, not %s" % type(result))
                iter_had_result = True
                cls = result.classification
                if result.classification != "NOT_AN_EXCEPTION":
                    if not os.path.isfile(mutation_fn):
                        raise Exception("result reported before mutation written to disk")
                    results += 1
                if keep or result.classification != "NOT_AN_EXCEPTION":
                    if is_replay:
                        log_fn = "%s.log.xml" % os.path.basename(template_fn)
                        pkl_fn = "%s.pkl" % os.path.basename(template_fn)
                    else:
                        log_fn = "mutation_%08X.log.xml" % (iterno)
                        pkl_fn = "mutation_%08X.pkl" % iterno
                    with open(log_fn, "w") as logf:
                        logf.write("<log>\n")
                        logf.write("<classification>%s</classification>\n" % result.classification)
                        logf.write("<backtrace>\n")
                        for lso in result.backtrace:
                            logf.write("<sym>%s</sym>\n" % lso)
                        logf.write("</backtrace>\n")
                        logf.write("<text>\n")
                        logf.write(result.text)
                        logf.write("</text>\n")
                        logf.write("</log>\n")
                    if write_pickle:
                        with open(pkl_fn, "wb") as f:
                            pickle.dump(result, f)
                    if reduce:
                        with open(template_fn, "rb") as f:
                            mutation = f.read()
                        for r in reduce:
                            mutation = _reduce(project_inst, r, reduce_n,
                                               mutation, mutation_fn, result)
                        oresult = result
                        with open(mutation_fn, "wb") as f:
                            f.write(mutation)
                        result = project_inst.run_subject(mutation_fn)
                        if not project_inst.resultmatch(oresult, result):
                            raise Exception("Result didn't match post-reduce")
            elif reduce:
                log.warning("--reduce specified, but no failure was found")
            # remove the mutation if it didn't cause failure
            if not keep and (not iter_had_result or cls == "NOT_AN_EXCEPTION" or is_replay):
                delete(mutation_fn)
            iterno += 1
            if time.time() - print_time >= 10:
                print_time = time.time()
                print_progress(start_time, iterno, results)
                printed = True
            if timeout is not None:
                timeout_event.set()
                timeout_continue.wait()
            do_deletes()
    except KeyboardInterrupt:
        log.info("User interrupt")
    finally:
        if not printed:
            print_progress(start_time, iterno, results)
        elapsed_time = time.time() - start_time
        log.info("Ran %d iterations and found %d results in %.2fs", iterno, results, elapsed_time)
        project_inst.cleanup()
        project_inst.finish()
        done = True
        if timeout is not None:
            timeout_event.set()
        do_deletes()


def parse_args():
    # defaults
    local_fuzzing_min = 500
    local_fuzzing_max = 10
    local_iters = 10000

    def int_test(testfunc, msg):
        def _tested(val):
            r = int(val)
            if not testfunc(r):
                raise argparse.ArgumentTypeError(msg % val)
            return r
        return _tested
    positive_int = int_test(lambda x: x > 0, "Expecting integer > 0, not %r")
    non_negative_int = int_test(lambda x: x >= 0, "Expecting integer >= 0, not %r")

    def any_not_none(*args):
        return bool([i for i in args if i is not None])

    # define option parser
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-g", "--aggr", type=positive_int,
        help="Aggression (sets both min and max aggression, lower is higher)")
    #argparser.add_argument("-c", "--crash", help="Read in a pickled alf.FuzzResult object "
    #    "and check it against a replay result (implies --replay)")
    argparser.add_argument("-i", "--iterations", type=non_negative_int,
        help="Number of iterations to perform (default: %d, 0 == forever)" % local_iters)
    argparser.add_argument("-k", "--keep-mutations", action="store_true",
        help="Keep all mutations, even those that don't cause a crash")
    argparser.add_argument("-x", "--max-aggr", type=positive_int,
        help="Maximum aggression (default %d, lower is higher)" % local_fuzzing_max)
    argparser.add_argument("-n", "--min-aggr", type=positive_int,
        help="Minimum aggression (default %d, lower is higher)" % local_fuzzing_min)
    argparser.add_argument("-l", "--pickle-result", action="store_true",
        help="Pickle alf.FuzzResult objects for later comparison")
    argparser.add_argument("--reduce", help="Reduce the given testcase "
        "(implies --replay and --verbose). Takes a comma separated list of reducers to run. "
        "Available reducers: (%s)" % ", ".join(sorted(reducers.keys())))
    argparser.add_argument("--reducen", type=positive_int, default=None,
        help="Target must crash in the same way N times before a testcase will be accepted in "
        "the reduction loop (for semi-reproducible testcases).")
    argparser.add_argument("-r", "--replay", action="store_true",
        help="Replay mode, shortcut for --aggr 0 --iterations 1")
    argparser.add_argument("-t", "--timeout", type=positive_int,
        help="Set a hard timeout per iteration (default: None)")
    argparser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    argparser.add_argument("project_name", help="Name of project to execute")
    argparser.add_argument("template_or_directory", help="Template or directory of test cases "
        "(directory implies --replay)")

    # parse options
    opts = argparser.parse_args()

    if os.path.isdir(opts.template_or_directory):
        if os.stat(opts.template_or_directory).st_size:
            opts.replay = True
        else:
            argparser.error("argument template_or_directory: Test case directory is empty.")
    elif not os.path.isfile(opts.template_or_directory):
        argparser.error("argument template_or_directory: Template/Test case file does not exist.")

    if opts.reduce:
        opts.replay = True
        opts.verbose = True
        opts.reduce = [s.strip() for s in opts.reduce.split(",")]
        if not opts.reducen:
            opts.reducen = 1 # default
        if not opts.reduce:
            argparser.error("no reducers specified")
    elif opts.reducen:
        argparser.error("--reducen can only be used with --reduce")
    if opts.aggr is not None and any_not_none(opts.min_aggr, opts.max_aggr):
        argparser.error("argument -g/--aggr: excludes --min-aggr and --max-aggr")
    if opts.replay and any_not_none(opts.aggr, opts.min_aggr, opts.max_aggr, opts.iterations):
        argparser.error("argument -r/--replay: excludes --min-aggr, --max-aggr, --aggression, "
                        "and --iterations")
    if opts.replay:
        opts.aggr = 0
        opts.iterations = 1
    elif opts.iterations is None:
        opts.iterations = local_iters
    if opts.aggr is not None:
        opts.min_aggr = opts.aggr
        opts.max_aggr = opts.aggr
    if opts.min_aggr is None:
        opts.min_aggr = local_fuzzing_min
    if opts.max_aggr is None:
        opts.max_aggr = local_fuzzing_max

    return opts, argparser.error


def load_project(project_name):
    # load project and check that it looks okay
    try:
        importlib.import_module(project_name)
    except ImportError as e:
        try:
            #TODO: relative module imports in a projects/Project will fail for some reason
            importlib.import_module("projects.%s" % project_name)
        except ImportError as e:
            log.error("Failed to import project %s", project_name, exc_info=1)
            sys.exit(1)
    if len(_registered) != 1:
        log.error("Project must register itself using alf.register(). "
                  "%d projects registered, expecting 1.", len(_registered))
        sys.exit(1)
    project_cls = _registered.pop()
    if not issubclass(project_cls, Fuzzer):
        raise TypeError("Expecting a Fuzzer, not '%s'" % type(project_cls))
    return project_cls


def local_run():
    opts, arg_error = parse_args()
    if opts.verbose:
        log.getLogger().setLevel(log.DEBUG)
    proj_cls = load_project(opts.project_name)
    if opts.reduce:
        for r in opts.reduce:
            if r not in reducers:
                arg_error("unknown reducer: \"%r\"" % r)

    tmp_wd = os.getcwd()
    if os.path.isdir(opts.template_or_directory):
        test_dir = os.path.abspath(opts.template_or_directory)
        tests = [os.path.join(test_dir, test) for test in os.listdir(opts.template_or_directory)]
        run_folder = "%s_%s_dir_replay" % (time.strftime("%Y%m%d-%H%M%S"), opts.project_name)
    else:
        tests = [opts.template_or_directory]
        run_folder = "%s_%s_local" % (time.strftime("%Y%m%d-%H%M%S"), opts.project_name)

    os.mkdir(run_folder)
    for template_fn in tests:
        template_fn = os.path.abspath(template_fn)
        os.chdir(run_folder)
        main(opts.project_name, proj_cls(template_fn), run_folder, template_fn,
             opts.iterations, opts.min_aggr, opts.max_aggr, opts.keep_mutations, opts.timeout,
             opts.pickle_result, opts.reduce, opts.reducen)
        os.chdir(tmp_wd)

