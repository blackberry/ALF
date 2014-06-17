################################################################################
# Name   : XmlAttributeFuzz
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
################################################################################
from random import randint

from .ValueFuzz import StringFuzzer, IntegerFuzzer, FuzzableInteger

################################################################################
# Classes
################################################################################
class XmlFuzzableAttribute(object):
    """
    XmlFuzzableAttribute is a description of an element attribute which
    is fuzzable for an element like this:
    '<element attribute="value" ... >'

    Not expected to be exported, only used to preserve state between
    :func:`find_xmlattrs` and :func:`fuzz_xmlattrs`.

    name:   the attribute

    value:  the value, either str or FuzzableInteger

    fileid: the xml file identifier (used to map from attributes -> files)

    start:  the file position of the start of 'value'

    end:    the file position of the end of 'value'
    """
    def __init__(self, name, value, element, fileid, start, end):
        self.name = name
        self.value = value
        self.element = element
        self.fileid = fileid
        self.start = start
        self.end = end
    def fuzzed_value(self, strfuzz, intfuzz):
        """fuzz and return the attribute as a string"""
        if isinstance(self.value, str):
            return strfuzz.fuzz_value(self.value)
        else:
            return intfuzz.fuzz_value(self.value)

################################################################################
# Functions
################################################################################

def find_xmlattrs(files):
    """
    This function scans a set of XML documents and identifies all of
    the element attributes for later fuzzing. The XML documents are
    given in a list of dicts, each having a ``data`` field and any
    number of other user defined fields to identify the file.

    The result is a list of opaque objects identifying the fuzzable
    attributes, which should be used as input to :func:`fuzz_xmlattrs`.
    """
    attributes = []
    for fileid, f in enumerate(files):
        file_data = f["data"]
        if file_data.startswith("<?"):
            off = file_data.find("?>") + 2
        else:
            off = 0
        try:
            while True:
                # find the next element starting with '<' (st) and ending with '>' (en)
                st = file_data.index("<", off)
                en = file_data.index(">", st)
                off = en + 1

                # find a space within the element
                sp = file_data.find(" ", st, en)
                if sp == -1:
                    continue

                # extract element name
                # (don't really need this, don't bother for now)
                element = file_data[st+1:sp]
                sp += 1

                # find all the attributes within this element
                while True:
                    # find the start and end of the value
                    try:
                        eq = file_data.index("=\"", sp, en)
                        name = file_data[sp:eq] # extract the attribute name
                        stq = eq + 2 # first char in the value (start quote)
                        enq = file_data.index("\"", stq, en) # end quote pos
                    except ValueError:
                        break
                    val = file_data[stq:enq] # extract the attribute value
                    sp = enq + 2 # move sp past the end of the end quote
                    # skip xml namespace attributes
                    if name.startswith("xmlns"):
                        continue
                    # cascade through the try blocks to find what kind of value this is
                    try:
                        val = FuzzableInteger(val)
                    except ValueError:
                        # leave val as a string if we can't create a FuzzableInteger from it
                        pass
                    # got everything, add to the result list
                    attributes.append(XmlFuzzableAttribute(name, val, element, fileid, stq, enq))
        except ValueError:
            pass
    return attributes

def fuzz_xmlattrs(files, attributes, aggression, strfuzzer=None, intfuzzer=None):
    """
    This method fuzzes the set of attributes found by
    :func:`~find_xmlattrs`.  The *files* parameter should be the same
    one given in :func:`~find_xmlattrs`, and the *attributes* parameter
    should be the list returned by the same.

    *aggression* is the inverse of the number of attributes to mutate
    as a ratio of the total number of attributes found. (ie.
    num_attrs/aggression == number of attrs to mutate).  Note that in
    this mode, aggression is statistical, so even an *aggression* of 1
    will not hit every attribute in the input.

    *strfuzzer* and *intfuzzer* are optional instances of
    :class:`~StringFuzzer` and :class:`~IntegerFuzzer` to be used on
    their respective types.  If not specified, one of each will be
    instantiated using the default parameters for each.

    The result is a mutated copy of *files*.
    """
    if not aggression:
        return files

    if strfuzzer is None:
        strfuzzer = StringFuzzer()
    if intfuzzer is None:
        intfuzzer = IntegerFuzzer()

    result = []
    nattributes = len(attributes)
    if aggression > 0:
        fuzzable = nattributes / aggression
    else:
        fuzzable = -aggression

    fuzzes = sorted(set(randint(0, nattributes-1) for _ in range(fuzzable)))
    fuzzes.reverse()

    try:
        tofuzz = attributes[fuzzes.pop()]
    except (IndexError, AttributeError):
        tofuzz = None
    for i, cf in enumerate(files):
        if tofuzz is None or tofuzz.fileid != i:
            result.append(cf)
        else:
            off = 0
            fileparts = []
            try:
                while tofuzz.fileid == i:
                    fileparts.append(cf["data"][off:tofuzz.start])
                    off = tofuzz.end
                    fileparts.append(tofuzz.fuzzed_value(strfuzzer, intfuzzer))
                    tofuzz = attributes[fuzzes.pop()]
            except IndexError:
                tofuzz = None
            fileparts.append(cf["data"][off:])
            newf = dict(cf)
            newf["data"] = "".join(str(f) for f in fileparts)
            result.append(newf)
    return result

