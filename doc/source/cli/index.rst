Command-line tools
==================

WHAD provides two types of command-line tools:

* generic command-line tools named in the form *whad<tool>*: these tools can
  be used with any WHAD device and may provide cross-protocol features or manage
  any WHAD device (**whadup** for instance).

* domain-specific tools named in the form of *w<domain>-<tool>*: these tools can
  be used with any WHAD device that supports a specific domain (**wble-central**
  for instance).


Generic tools
-------------

.. toctree::
    :maxdepth: 1

    generic/whadup
    generic/wplay
    generic/wsniff
    generic/wfilter
    generic/wextract
    generic/wdump
    generic/wshark
    generic/wanalyze
    generic/winject
    generic/wserver

Bluetooth Low Energy tools
--------------------------

.. toctree::
    :maxdepth: 1

    ble/ble-central
    ble/ble-periph
    ble/ble-proxy
    ble/ble-spawn
    ble/ble-connect

Logitech Unifying tools
-----------------------

.. toctree::
    :maxdepth: 1

    unifying/wuni-scan
    unifying/wuni-mouse
    unifying/wuni-keyboard



Tool chaining and packet processing chain
-----------------------------------------

WHAD provides a way to chain tools in order to create complex behaviors, to enable
tool modularity or simply to let the user arrange them to reach a specific goal.
The shell operator `|` is used to perform this chaining, as shown in the example
below:

.. code-block:: text

    $ wble-connect -i hci1 11:22:33:44:55:66 | wshark | wble-central profile

In this example, `wble-connect` will initiate a connection to the device identified
by the Bluetooth Device address `11:22:33:44:55:66`, spawn a wireshark that will
monitor every Bluetooth Low Energy packet sent or received thanks to `wshark`,
and then use `wble-central` to enumerate the target services and characteristics.

Bidirectional packet processing chain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Similarly to *gnuradio*, *WHAD* allows the creation of a **packet processing chain**
using basic tools. This processing chain is created by chaining WHAD tools with
pipes character, like anyone would do on a UNIX-like system. By doing so the
different tools will be connected and will exchange various messages back and forth,
including protocol packets (or PDUs), events and more.

Most of the generic CLI tools however are able to manipulate packets exchanged
in this *processing chain*, allowing them to be dumped into a file or simply
monitored in real-time with an instance of *Wireshark* for instance.
This gives the ability to the user to play with the exchanged data without having
to code a tool, by simply building custom processing chains.

From a technical perspective, this bidirectional chain is established using Unix
sockets: each time a tool needs to connect to another tool, it creates a Unix socket
and awaits the other tool to connect to it. Therefore, any tool in the processing
chain can receive messages but also send messages to the previous or to the next
tool, while Unix pipes do not allow that by definition.


A sequential processing chain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In a processing chain, tools are all started and await to connect to the previous
tool. Consider the following processing chain:

```
TOOL_A | TOOL_B | TOOL_C
```

All tools will be executed at the same time, but ``TOOL_B`` and ``TOOL_C`` will
wait for their respective previous tools the required information to connect to
their respective Unix socket server in order to start processing messages. Whereas
this processing chain is created and started, ``TOOL_A`` needs to pass to ``TOOL_B``
the required information for this latter to connect to it and start processing
messages, forcing ``TOOL_B`` to start processing messages once a specific
condition is met.

This allows to sequence a series of operations, depending on the order of the tools
used in the processing chain. Let's analyze deeper what is going on with the
previous example:

.. code-block:: text

    $ wble-connect -i hci1 11:22:33:44:55:66 | wshark | wble-central profile

First, ``wble-connect`` initiates a connection to the target device, but it will
spawn a Unix socket server only once this connection is successfully established.
Once this socket server is active, ``wshark`` will connect to it and spawns another
Unix socket server of its own, providing ``wble-central`` with the information
it needs to connect to its Unix socket server. ``wble-connect`` connects
to ``wshark``'s Unix socket server and is now able to send BLE PDUs into the
already established connection. Packets can travel from ``wble-central`` to
``wble-connect`` back and forth, while ``wshark`` simply monitor them and acts
as a basic proxy.

In this example, ``wble-central`` cannot be chained with another WHAD-enable CLI
tool as it is intended to produce a very specific output for the user.
