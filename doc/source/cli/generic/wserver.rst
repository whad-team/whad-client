wserver: generic TCP tunneling tool
======================================

``wserver`` is a tool designed to expose any WHAD device through a TCP server,
allowing WHAD tools to connect to it and access the underlying device as it were
physically present on the user machine while it is connected on another one.

.. warning::

    TCP tunneling may introduce some latency that is not compatible with some protocols
    like Logitech Unifying. This may improve in the future, but for now this is a known
    limitation.

Usage
-----

.. code-block:: text

    wserver -i <INTERFACE> -p PORT [-a IP_ADDRESS]

Command-line options
^^^^^^^^^^^^^^^^^^^^

**wserver** supports the following options:

* ``--address`` (``-a``): specify an IP address to listen on (default: `127.0.0.1` or `::1`)
* ``--port`` (``-p``): specify the port to use (default: `12345`)

.. include:: debug-options.rst

Exposing a WHAD device over TCP
-------------------------------

Using ``wserver``, any compatible device may be accessible through the network.
First, we start ``wserver`` with the target WHAD device:

.. code-block:: text

    $ wserver -i uart0 -a 192.168.1.2 -p 4444

Then, we can access this device over TCP:

.. code-block:: text

    $ whadup tcp:192.168.1.2:4444
    [i] Connecting to device ...
    [i] Device details

    Device ID: c3:9c:c2:8d:c3:97:c2:88:c2:9c:35:62:c2:9d:c2:a6:c2:aa:c2:a7:c2:be:c3:be:09:04:32
    Firmware info:
    - Author : Romain Cayre
    - URL : https://github.com/whad-team/butterfly
    - Version : 1.0.1

    [i] Discovering domains ...
    [i] Domains discovered.

    This device supports Bluetooth LE:
    - can sniff data
    - can inject packets
    - can hijack communication
    - can simulate a role in a communication

    List of supported commands:
    - SetBdAddress: can set BD address
    - SniffAdv: can sniff advertising PDUs
    - ReactiveJam: can reactively jam PDU on a single channel
    - SniffConnReq: can sniff a new connection
    [...]
