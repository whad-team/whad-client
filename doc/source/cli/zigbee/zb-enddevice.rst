wzb-enddevice: ZigBee End device tool
=====================================

``wzb-enddevice`` is a ZigBee end device emulation tool that can connect to a
target ZigBee network, discover the neighbouring nodes and send them ZCL
commands. 

.. contents:: Table of Contents
    :local:
    :depth: 1

Usage
-----

.. code-block:: text

    wzb-enddevice [OPTIONS] ([COMMAND] ([COMMAND ARGS]))

``wzb-enddevice`` accepts one or more options, and requires a valid command as its
first parameter. This command may or may not accepts arguments.

Command-line options
--------------------

**wzb-enddevice** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use
* ``--network-panid`` (``-t``): specifies a target extended ZigBee network PAN ID (64 bits)
* ``--file`` (``-f``): provides a script to execute

Discover ZigBee networks
------------------------

