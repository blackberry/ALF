ALF is a framework created for software developers, testers and security researchers for testing their software through fuzzing.  This release includes the API for creating a fuzzer and running it locally. Other components include a client/server distribution system for maintaining a fuzzing cloud, and a web-based triage workflow for logging results in external bug trackers.

The API includes functions for mutation and generation of testcases, and debugging using WinDBG or GDB.

# Concepts

ALF uses the concept of a fuzzing iteration as the central unit of work.  A fuzzer usually has a setup operation, many fuzzing iterations, and a final cleanup operation.  Each stage consists of the following steps (some may not apply in all situations):

## Setup

* Read in a template testcase (for mutation)
* Initialize the target

## Iteration

* Return the target to a known state
* Create a fuzzed testcase using either mutation or generation
* Run the target against the testcase
* Monitor for crash (and record)

## Cleanup

* Close the target
* Delete any temporary files


This structure has an emphasis on simplicity (for maintenance) and self-containment (for running in a cloud).

# Installation

    pip install -r requirements.txt
    git clone https://github.com/jfoote/exploitable.git
    cd exploitable
    sudo gdb -batch -ex 'py sys.argv=["","install"]' -ex 'py execfile("setup.py")'

We do the exploitable install this way to install the plugin in GDB's data directory using the python interpreter GDB is linked against.

# License

This software is available under the [Apache 2.0 License](http://www.apache.org/licenses/LICENSE-2.0)

# Disclaimer

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
