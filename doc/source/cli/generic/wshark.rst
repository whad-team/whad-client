wshark: generic wireshark monitoring tool
=========================================

``wshark`` is a simple tool that captures packets from the current processing chain
and displays them in real-time in an instance of *Wireshark*. The current wireless
protocol and packet format is infered from previous tools in the chain.

``wshark`` supports every protocol defined in WHAD and includes some custom dissectors
that are loaded at runtime. *Wireshark* still needs to be installed as it is
required by this tool.

Usage
-----

.. code-block:: text

    ... | wshark | ...

.. include:: ../generic/debug-options.rst

Simple example
--------------

To monitor the packets sent between a BLE client that runs on host and a target
BLE device, ``wshark`` is the way to go. The following command connects to a BLE
device and then discovers its services and characteristics while an instance of
wireshark is launched to monitor the traffic in real-time:

.. code-block:: text

    $ wble-connect -i hci0 00:11:22:33:44:55 | wshark | wble-central profile

