################################################################################
# Name   : ALF Development Kit (ADK) Main
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
import logging
import os
import alf.local

DEBUGMEM = bool(os.getenv("DEBUGMEM", False))

if DEBUGMEM:
    import gc
    gc.set_debug(gc.DEBUG_LEAK)

alf.local.local_run()

if DEBUGMEM:
    logging.info("Uncollectable: %d", gc.collect())
    for x in gc.garbage:
        logging.info(type(x))
        logging.info("   %s", str(x)[:80])
        logging.info("   %s", gc.get_referrers(x))

