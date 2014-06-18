################################################################################
# Name   : qemu -- base for BBSAAT Fuzzers running in QEMU
# Author : Tyson Smith & Jesse Schwartzentruber
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
import subprocess
import sys
import pickle
import distutils.spawn
from io import StringIO

from . import _common, SockPuppet

ALF_BASE = os.getcwd()

def loads(data, from_module=None):
    up = pickle.Unpickler(StringIO(data))
    def find_global(module, cls):
        if module == "copy_reg" and cls == "_reconstructor":
            return copy_reg._reconstructor
        if module == "__builtin__":
            return getattr(__builtins__, cls)
        if from_module is not None:
            return getattr(from_module, cls)
        return globals()[cls]
    up.find_global = find_global
    return up.load()

def _remote_init(working_dir):
    global pickle
    import pickle
    import sys
    import shutil
    import os
    if not os.path.isdir(working_dir):
        os.mkdir(working_dir)
    sys.path.append(working_dir)
    shutil.move("_common.py", working_dir)
    shutil.move("_gdb.py", working_dir)
    shutil.move("cmds.gdb", working_dir)
    # setup CERT exploitable
    exp_lib_dir = os.path.join(working_dir, "exploitable", "lib")
    os.makedirs(exp_lib_dir)
    shutil.move("exploitable.py", os.path.join(working_dir, "exploitable"))
    shutil.move("__init__.py", exp_lib_dir)
    shutil.move("analyzers.py", exp_lib_dir)
    shutil.move("classifier.py", exp_lib_dir)
    shutil.move("elf.py", exp_lib_dir)
    shutil.move("gdb_wrapper.py", exp_lib_dir)
    shutil.move("rules.py", exp_lib_dir)
    shutil.move("tools.py", exp_lib_dir)
    shutil.move("versions.py", exp_lib_dir)
    os.chdir(working_dir)
    global _common
    global _gdb
    import _common
    import _gdb

def _remote_gdb_func(cmd, env, timeout, idle_limit):
    return pickle.dumps(_gdb.run_with_gdb(cmd, env=env, timeout=timeout, idle_limit=idle_limit), pickle.HIGHEST_PROTOCOL)

def _remote_run_func(cmd, env, timeout, memory_limit, idle_limit):
    return pickle.dumps(_common.run(cmd, env=env, timeout=timeout, memory_limit=memory_limit, idle_limit=idle_limit), pickle.HIGHEST_PROTOCOL)

class QEmuTarget(SockPuppet.Controller):
    ARCH_ARM_LINUX = 0
    REMOTE_WORKING_DIR = "/tmp/alf"
    QEMU_BIN = ""
    QEMU_PATH = ""
    log.basicConfig(level=log.INFO)
    def __init__(self, arch=ARCH_ARM_LINUX, memory=1024, debug_host=False, debug_target=False, qemu_bin=None, img_dir=".", img_fs="linux-rootfs.img", img_kernel="linux-kernel"):
        SockPuppet.Controller.__init__(self, debug=debug_host)
        self.debug_target = debug_target
        if qemu_bin is not None:
            self.QEMU_BIN = qemu_bin
        elif platform.system() in ["Windows", "Linux"]:
            self.QEMU_BIN = distutils.spawn.find_executable("qemu-system-arm")
        else:
            raise RuntimeError("Unsupported platform: %s" % platform.system())
        assert self.QEMU_BIN is not None and os.path.isfile(self.QEMU_BIN), "Missing QEMU executable at %r" % self.QEMU_BIN
        if arch == self.ARCH_ARM_LINUX:
            img_fs = os.path.join(img_dir, "linux-rootfs.img")
            img_kernel = os.path.join(img_dir, "linux-kernel")
            assert os.path.isfile(img_fs), "Missing %s" % img_fs
            assert os.path.isfile(img_kernel), "Missing %s" % img_kernel
            cmd = [self.QEMU_BIN, "-M", "vexpress-a9", "-snapshot", "-m", str(memory),
                   "-kernel", img_kernel, "-sd", img_fs, "-append", "root=b300 console=ttyAMA0",
                   "-net", "nic", "-net", "user,hostfwd=tcp::2222-:22", "-serial", "stdio",
                   "-display", "none"]
        else:
            raise RuntimeError("Unsupported Architecture")
        if debug_target:
            self.target_out = sys.stdout
        else:
            self.target_out = open(os.devnull, "w")
        try:
            self.qemu_proc = subprocess.Popen(cmd, shell=False, stdout=self.target_out,
                                              stderr=self.target_out)
            self.connect()
            if debug_target:
                self.debug_client()
            self.send_file(SockPuppet.__file__, "/root/SockPuppet.py")
            self.send_quit()
            self.disconnect()
            self.connect()
            if debug_target:
                self.debug_client()
            # Send required gdb wrapper
            alf_debug_dir = os.path.join(ALF_BASE, "alf", "debug")
            # Send required gdb wrapper
            self.send_file(os.path.join(alf_debug_dir, "_common.py"))
            self.send_file(os.path.join(alf_debug_dir, "_gdb.py"))
            self.send_file(os.path.join(alf_debug_dir, "cmds.gdb"))
            # Send CERT exploitable to target
            exploitable_dir = os.path.join(ALF_BASE, "lib", "exploitable")
            self.send_file(os.path.join(exploitable_dir, "exploitable.py"))
            exploitable_dir = os.path.join(exploitable_dir, "lib")
            self.send_file(os.path.join(exploitable_dir, "__init__.py"))
            self.send_file(os.path.join(exploitable_dir, "analyzers.py"))
            self.send_file(os.path.join(exploitable_dir, "classifier.py"))
            self.send_file(os.path.join(exploitable_dir, "elf.py"))
            self.send_file(os.path.join(exploitable_dir, "gdb_wrapper.py"))
            self.send_file(os.path.join(exploitable_dir, "rules.py"))
            self.send_file(os.path.join(exploitable_dir, "tools.py"))
            self.send_file(os.path.join(exploitable_dir, "versions.py"))
            self.run_code(_remote_init, self.REMOTE_WORKING_DIR)
        except RuntimeError:
            self._kill_qemu()
            raise
        finally:
            if not debug_target:
                self.target_out.close()

    def _kill_qemu(self):
        if platform.system() == "Windows":
            with open(os.devnull, "w") as fp:
                subprocess.call(["taskkill", "/IM", os.path.basename(self.QEMU_BIN), "/f"],
                                stdout=fp, stderr=fp)

    def close(self):
        try:
            self.send_quit()
            self.disconnect()
            if not self.debug_target:
                self.target_out.close()
        finally:
            self._kill_qemu()

    def run_with_gdb(self, cmd, env=None, timeout=_common.DEFAULT_TIMEOUT, idle_limit=None):
        return loads(self.run_code(_remote_gdb_func, cmd, env, timeout, idle_limit), _common)

    def run(self, cmd, env=None, timeout=_common.DEFAULT_TIMEOUT, memory_limit=None, idle_limit=None):
        return loads(self.run_code(_remote_run_func, cmd, env, timeout, memory_limit, idle_limit), _common)

if __name__ == "__main__":
    log.basicConfig(level=log.DEBUG)
    target = QEmuTarget()
    for _ in range(10):
        result = target.run(["ls"])
    result = target.run_with_gdb(["ls"])
    target.close()
