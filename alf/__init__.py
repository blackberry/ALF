################################################################################
# Name   : ALF Development Kit (ADK)
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
import os
import shutil
import stat
from .reduce import add_reducer


__all__ = ("schedule_system_restart", "register", "add_reducer", "Fuzzer",
           "rm_full_dir", "LSO", "FuzzResult", "delete", "remove", "unlink")
_force_system_restart = False
_registered = []


def schedule_system_restart():
    """
    This can be called by a plugin to request that a system restart be
    performed after the current job is complete and reported.  The
    system will not be restarted when running in local mode.
    """
    global _force_system_restart
    _force_system_restart = True


def register(cls):
    """
    This must be called by a plugin in order to register the
    implementation of :class:`Fuzzer` with the ALF engine.  The
    registered class will be instantiated and used in the main loop.
    """
    if not issubclass(cls, Fuzzer):
        raise TypeError("Expecting a Fuzzer, not '%s'" % type(cls))
    _registered.append(cls)


class Fuzzer(object):
    """
    This is the base-class for ALF project plugins.

    The input template filename is given as an input when the class is
    instantiated, but is written multiple times by
    :meth:`~do_iteration`.  Users should save either the template data
    or filename as an attribute if needed for later use.
    """
    def __init__(self, template_fn):
        raise NotImplementedError()

    def do_iteration(self, mutation_fn, aggression):
        """
        This method is called with an output mutation filename and a
        real aggression (see :ref:`aggression`) indicating the amount
        of aggression the fuzzing algorithm should use.  *mutation_fn*
        is unique for every invokation of :meth:`do_iteration`.

        It is an error for this method not to write the mutated
        template to *mutation_fn* before returning a result.  If a
        result is not found, the mutation filename may be written to
        if needed, but it is not required.

        If a notable result is found, it should be returned as a
        :class:`FuzzResult` instance.  This will be stored and reported
        to the ALF central server at the next check-in interval.  A
        return of None indicates a result was not found.

        The filenames of any temporary files or folders created during
        execution can be safely removed using :func:`alf.delete`.  This
        is safer than using :func:`os.remove` or :func:`shutil.rmtree`
        directly.  *mutation_fn* does not need to be deleted, it is
        cleaned up automatically.
        """
        raise NotImplementedError()

    def cleanup(self):
        """
        This method is called after all iterations are complete and
        periodically if the disk appears to be filling up.  It should
        clean up any temporary files written by the target to a global
        location (such as ``/tmp`` or ``%TEMP%``), but not files which
        are necessary to run.  See also :meth:`~Fuzzer.on_exit`.
        """
        raise NotImplementedError()

    def on_exit(self):
        """
        This method is called after all iterations are complete.  It
        should clean up any temporary files created during
        :class:`Fuzzer` which are necessary to run
        :meth:`~Fuzzer.do_iteration`.  See also :meth:`~Fuzzer.cleanup`.
        """
        pass

    @staticmethod
    def resultmatch(result, other):
        return result == other


def rm_full_dir(path, ignore_errors=False):
    """
    This function is used to remove a directory and all files and
    directories within it (like `rm -rf`).
    """
    if os.path.isdir(path):
        try:
            os.chmod(path, os.stat(path).st_mode | stat.S_IRWXU
                                                 & ~stat.S_ISVTX)
        except OSError:
            pass
        f_last = 0
        while True:
            f_count = 0
            for root, d_names, f_names in os.walk(path):
                try:
                    os.chmod(root, os.stat(root).st_mode | stat.S_IRWXU
                                                         & ~stat.S_ISVTX)
                except OSError:
                    pass
                for fs_name in f_names + d_names:
                    target = os.path.join(root, fs_name)
                    try:
                        os.chmod(target, os.stat(target).st_mode
                                              | stat.S_IRWXU
                                              & ~stat.S_ISVTX)
                    except OSError:
                        pass
                    f_count += 1
                f_count += 1
            # do this until we get the same count twice, ie. all files we can
            # chmod our way into have been found
            if f_last == f_count:
                break
            f_last = f_count
        shutil.rmtree(path, ignore_errors)


from . import debug

#TODO: shouldn't all these live in alf or alf common and be imported by alf.debug?

LSO = debug.LSO
FuzzResult = debug.FuzzResult
delete = debug._common.delete
# undoc aliases
remove = delete
unlink = delete

