********************************************
ALF Developer API
********************************************

API Overview
============

This module provides an API for software developers, testers, and security
researchers to implement a plugin for fuzzing with ALF. This API is intended to
provide a rich set of capabilities for template mutation and fault detection,
allowing the user to interface their project to the ALF distributed fuzzing
cloud quickly and easily. The API currently supports Python 2.7.

To create an ALF plugin, developers should define a class which inherits from
:class:`alf.Fuzzer`, and then register that class using :func:`alf.register`.
The :meth:`~alf.Fuzzer.do_iteration` method of the registered
:class:`~alf.Fuzzer` instance will be called every iteration in order to
mutate the template, deliver the mutation to the target, and detect whether
faults occur. Each plugin is expected to override
:meth:`~alf.Fuzzer.do_iteration`. Facilities are provided to assist with template
mutation in the :mod:`alf.fuzz` submodule. Target launching and fault
detection functions are provided in the :mod:`alf.debug` submodule.

Packaging
=========

ALF plugins are packaged in a Zip file, which must contain a folder with the same name
as the project. This folder must be an importable Python 2.7 package, and the *__init__.py*
of that package must call :func:`alf.register` when loaded.

.. _aggression:

Aggression
==========

It is important to understand ALF's concept of *aggression*.
It specifies the amount of random change (mutation) applied to a template file.
Aggression is specified as a positive natural number (an integer greater than zero).

A "template" is a file containing input in some form for a test subject program.
One "iteration" of fuzzing is performed by copying and randomly changing the template,
producing a "mutation" which is then supplied to the test subject program.
Aggression applies while the copied template is being randomly changed.
This is typically done by repeated *mutation steps* applied to the copied template file.
Each mutation step randomly chooses and changes a few bytes or characters in the file.
Many mutation steps applied in succession result in the accumulation of many small changes.

The process is roughly analogous to the effect of mutating radiation on a physical sample.
Each mutation step is like a "particle" that passes through the sample and changes it.
ALF's aggression can be thought of as "exposure control", with the aggression playing the role of
the distance the sample is from a "radiation source".
The larger the aggression's numeric value, the less mutation will be done on the copied template.
ALF's fuzzing library methods such as :meth:`~alf.fuzz.fuzz_xmlattrs`
or :meth:`~alf.fuzz.BinaryFileFuzzer.fuzz_data` accept an aggression parameter
which has this interpretation.

It is approximately true that the number of mutation steps ("particles") applied
varies inverse linearly with the aggression.  For example,
if a megabyte of binary data is fuzzed using an aggression of 100, there will be approximately
10,000 mutation steps, each of which has a uniform chance of "hitting" one of the bytes.  With an aggression
of 400, there will be about 2,500 steps.  Mutation steps accumulate, so a byte may be "hit" multiple times
during an aggressive mutation.

When a fuzzer is running under ALF control,
for each "fuzz run" the framework randomly chooses an aggression from a project-specific range,
and supplies it to the :meth:`~alf.Fuzzer.do_iteration` plug-in implementation.
If fuzz library methods are used, the plug-in should pass aggression on to the library.
If fuzz library methods are not used and mutation is done some other way,
aggression should be treated similarly:
aggression 1 should produce the wildest mutations,
and numerically larger values of aggression should produce less "wild" mutations.

Aggression 0 is a special case.  When aggression is zero, no mutation should be performed: the copied template
file should be used unchanged.  It is as if the sample was an infinite distance from the radiation.
Plug-ins must ensure that they observe this "zero aggression" rule,
so that ALF can effectively reproduce previously recorded failures.
The ALF fuzzing library methods observe this "zero aggression" rule.

Running Locally
===============

An ALF plugin can be run locally for testing or offline fuzzing as follows::

   python -m alf <ProjectName> <template>

The *ProjectName* and *template* parameters are required. Additional options are available.
Particularly useful for reproducings failures is::

   python -m alf <ProjectName> <mutation> -g 0 -i 1

which locally runs a previously-mutated file for one iteration under the "zero aggression" rule.

Up-to-date help can be viewed by running::

   python -m alf -h

Templates
=========

Templates are used by projects to generate mutations. Each job requires a template
(even if it is unused by the project) and only one template can be used per job.
The distribution of the templates is handled by the ALF Server.
When running in local mode only the template specified on the command line will be used.
