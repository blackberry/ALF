################################################################################
# Name   : SockPuppet.py
# Author : Tyson Smith
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
import argparse
import pickle
import marshal
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import traceback
import types
import zlib

class SockPuppetBase(object):
    # DEFAULTS
    CHUNK_BUF = 4 * 1024 * 1024
    SOCK_BUF = 64 * 1024
    # COMMANDS
    ACK =    0
    CHUNK =  1
    CODE =   2
    DEBUG =  3
    EXCEPT = 4
    FILE =   5
    QUIT =   6
    RESULT = 7
    RETURN = 8
    RUN =    9

    def __init__(self, ip=None, is_server=False, port=1701, timeout=60, debug=False):
        self.conn = None
        self.ip = ip
        self.is_server = is_server
        self.port = port
        self.timeout = timeout
        self.debugging = debug
        log.basicConfig(level=log.INFO)
        if self.debugging and log.getLogger().level == log.INFO:
            self.toggle_debug()

    def connect(self):
        if self.is_server:
            log.debug("waiting for client to connect...")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', self.port))
            s.settimeout(0.1)
            start_time = time.time()
            s.listen(0)
            while True:
                try:
                    conn, _ = s.accept()
                    self.conn = conn
                    break
                except socket.timeout:
                    pass
                if self.timeout > 0 and time.time() - start_time >= self.timeout:
                    s.close()
                    raise RuntimeError("Timeout exceeded (%ds)" % self.timeout)
            self.conn.setblocking(True)
        else:
            log.debug("connecting to server (%s:%d)...", self.ip, self.port)
            self.conn = socket.create_connection((self.ip, self.port), self.timeout)

    def disconnect(self):
        log.debug("disconnecting")
        if self.conn:
            self.conn.close()

    def recv_data(self):
        data_remaining = struct.unpack("I", self.conn.recv(4))[0]
        if not data_remaining:
            log.debug("no data?!")
            return None
        log.debug("<- recving %d bytes", data_remaining)
        data = []
        while data_remaining:
            recv_bytes = data_remaining if data_remaining < self.SOCK_BUF else self.SOCK_BUF
            data.append(self.conn.recv(recv_bytes))
            data_len = len(data[-1])
            if data_len == 0:
                break
            data_remaining -= data_len
        data = pickle.loads("".join(data))
        if data["cmd"] != self.ACK:
            self.send_ack()
        return data

    def recv_file(self, data):
        name = os.path.join(data["path"], data["name"])
        data_remaining = data["size"]
        expected_chksum = data["chksum"]
        log.debug("receiving file: %s (%0.02fKB)", name, data_remaining/1024.0)
        chksum = 0
        with open(name, "wb") as fp:
            while data_remaining:
                data = self.recv_data()
                assert data["cmd"] == self.CHUNK, "Expecting data chunk."
                chksum = zlib.adler32(data["data"], chksum)
                fp.write(data["data"])
                data_remaining -= len(data["data"])
        if expected_chksum != chksum:
            raise RuntimeError("Checksum mismatch!")

    def send_ack(self):
        log.debug("ACK'ing")
        self.send_data({"cmd":self.ACK})

    def send_data(self, data):
        is_ack = (data["cmd"] == self.ACK)
        data = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)
        data_len = len(data)
        assert data_len < 0xFFFFFFFF, "Transfer too large!"
        log.debug("-> sending %d bytes", data_len)
        self.conn.sendall(struct.pack("I", data_len))
        self.conn.sendall(data)
        if not is_ack:
            assert self.recv_data()["cmd"] == self.ACK
            log.debug("ACK received")

    def send_file(self, src, dst=None):
        if not os.path.isfile(src):
            raise RuntimeError("%s does not exist!" % src)
        if dst is None:
            dst = os.path.basename(src)
        log.debug("sending file (%s) -> (%s)", src, dst)
        file_size = int(os.stat(src).st_size)
        chksum = 0
        with open(src, "rb") as fp:
            while fp.tell() < file_size:
                chksum = zlib.adler32(fp.read(self.CHUNK_BUF), chksum)
        data = {
                "cmd":self.FILE,
                "name":os.path.basename(dst),
                "path":os.path.dirname(dst),
                "size":file_size,
                "chksum":chksum
               }
        self.send_data(data)
        with open(src, "rb") as fp:
            data = {"cmd":self.CHUNK}
            while fp.tell() < file_size:
                data["data"] = fp.read(self.CHUNK_BUF)
                self.send_data(data)
                if len(data["data"]) < self.CHUNK_BUF:
                    break

    def toggle_debug(self):
        self.debugging = not self.debugging
        if self.debugging:
            log.getLogger().setLevel(level=log.DEBUG)
            log.debug("debugging enabled")
        else:
            log.debug("debugging disabled")
            log.getLogger().setLevel(level=log.INFO)

class Target(SockPuppetBase):
    def run(self):
        self.connect()
        try:
            while True:
                log.debug("waiting for command...")
                data = self.recv_data()
                if data["cmd"] == self.QUIT:
                    log.debug("QUIT (%d)", self.QUIT)
                    break
                elif data["cmd"] == self.DEBUG:
                    log.debug("DEBUG")
                    self.toggle_debug()
                elif data["cmd"] == self.FILE:
                    log.debug("FILE (%d)", self.FILE)
                    self.recv_file(data)
                elif data["cmd"] == self.RUN:
                    log.debug("RUN (%d)", self.RUN)
                    log.debug("running cmd: %s", " ".join(data["cmd_to_run"]))
                    with tempfile.TemporaryFile() as fp:
                        try:
                            proc = subprocess.Popen(data["cmd_to_run"],
                                                    shell=False,
                                                    stdout=fp,
                                                    stderr=fp)
                            data = {"cmd":self.RESULT}
                            data["code"] = proc.wait()
                            fp.seek(0)
                            data["output"] = fp.read()
                            log.debug("command returned: %d", data["code"])
                        except Exception:
                            e = sys.exc_info()
                            log.debug("except - %s: %s", e[0].__name__, e[1])
                            data = {"cmd":self.EXCEPT,
                                    "msg":e[1],
                                    "name":e[0].__name__,
                                    "tb":"".join(traceback.format_tb(e[2]))}
                    log.debug("sending results...")
                    self.send_data(data)
                elif data["cmd"] == self.CODE:
                    log.debug("CODE (%d)", self.CODE)
                    try:
                        func = types.FunctionType(marshal.loads(data["code"]), globals(),
                                                  data["name"], data["defaults"], data["closure"])
                        log.debug("%s() args:%s kwargs:%s", data["name"], data["args"], data["kwargs"])
                        data = {"cmd":self.RETURN, "value":func(*data["args"], **data["kwargs"])}
                    except Exception:
                        e = sys.exc_info()
                        log.debug("except - %s: %s", e[0].__name__, e[1])
                        data = {"cmd":self.EXCEPT,
                                "msg":e[1],
                                "name":e[0].__name__,
                                "tb":"".join(traceback.format_tb(e[2]))}
                    self.send_data(data)
                else:
                    log.debug("UNKNOWN (%s)", data)
                    raise RuntimeError("Unknown command: %d" % data["cmd"])
        finally:
            self.disconnect()

class Controller(SockPuppetBase):
    def __init__(self, *args, **kwargs):
        SockPuppetBase.__init__(self, is_server=True, *args, **kwargs)

    @staticmethod
    def _process_target_except(e_data):
        msg = "Client side exception.\n\n%s%s: %s" % (e_data["tb"], e_data["name"], e_data["msg"])
        return RuntimeError(msg)

    def run_cmd(self, cmd_to_run, cmd_timeout=120):
        log.debug("run cmd on target: %s", " ".join(cmd_to_run))
        data = {"cmd":self.RUN,
                "cmd_to_run":cmd_to_run,
                "timeout":cmd_timeout}
        self.send_data(data)
        log.debug("waiting for cmd results...")
        data = self.recv_data()
        if data["cmd"] == self.EXCEPT:
            log.debug("received exception")
            raise self._process_target_except(data)
        assert data["cmd"] == self.RESULT
        return (data["code"], data["output"])

    def run_code(self, function, *args, **kwargs):
        log.debug("%s() args:%s kwargs:%s on target", function.func_name, args, kwargs)
        data = {"cmd":self.CODE,
                "code":marshal.dumps(function.func_code),
                "name":function.func_name,
                "args":args,
                "kwargs":kwargs,
                "defaults":function.__defaults__,
                "closure":function.__closure__}
        self.send_data(data)
        log.debug("waiting for code to execute...")
        data = self.recv_data()
        if data["cmd"] == self.EXCEPT:
            log.debug("received exception")
            raise self._process_target_except(data)
        assert data["cmd"] == self.RETURN
        return data["value"]

    def send_quit(self):
        log.debug("sending QUIT")
        self.send_data({"cmd":self.QUIT})

    def debug_client(self):
        log.debug("sending DEBUG")
        self.send_data({"cmd":self.DEBUG})

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', default="localhost", help='server ip')
    parser.add_argument('--debug', action="store_true", dest="debug", default=False)
    parser.add_argument('--mode', default="server", help='mode: server or client')
    parser.add_argument('--port', type=int, default=1701, help='port')
    parser.add_argument('--timeout', type=int, default=0)

    args = parser.parse_args()

    if args.mode == "server":
        c = Controller(port=args.port, timeout=args.timeout, debug=args.debug)
        c.connect()
        try:
            c.send_quit()
        finally:
            c.disconnect()
        log.debug("SERVER EXIT")
    elif args.mode == "client":
        t = Target(ip=args.ip, port=args.port, debug=args.debug)
        t.run()
        log.debug("CLIENT EXIT")
