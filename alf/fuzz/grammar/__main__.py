##############################################################################
# Name   : ALF grammar module, CLI
# Author : Jesse Schwartzentruber
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
##############################################################################
import argparse
import os.path
import re
import sys

from . import Grammar

argp = argparse.ArgumentParser(description="Generate a testcase from a grammar")
argp.add_argument("input", type=argparse.FileType('r'), help="Input grammar definition")
argp.add_argument("output", type=argparse.FileType('w'), nargs="?", default=sys.stdout, help="Output testcase")
argp.add_argument("-f", "--function", action="append", nargs=2, help="Function used in the grammar (eg. -f filter lambda x:x.replace('x','y')", default=[])
args = argp.parse_args()
args.function = {func: eval(defn) for (func, defn) in args.function}
args.output.write(Grammar(args.input.read(), path=os.path.dirname(args.input.name), **args.function).generate())

