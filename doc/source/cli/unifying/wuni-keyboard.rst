wuni-keyboard: Logitech Unifying keyboard tool
==============================================

``wuni-keyboard`` synchronizes with a connected Logitech Unifying keyboard dongle
and sends spoofed keypresses.

Usage
-----

.. code-block:: text

    wuni-keyboard -i <INTERFACE> [-a/--address ADDRESS] [-p/--payload] [-d/--ducky] [-l/--locale] [-k/--key]

A compatible WHAD *interface* is required to listen to packets transmitted by a
Logitech Unifying device and send spoofed packets. Device address (*ADDRESS*)
is mandatory as it specifies the wireless mouse device to target.


Command-line options
--------------------

**wuni-keyboard** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use to connect to the target device
* ``--no-color``: disables colors in output
* ``--address`` (``-a``): specify the target wireless keyboard address
* ``--payload`` (``-p``): specify a text payload to send, followed by a press on *ENTER*
* ``--ducky`` (``-d``): specify a *DuckyScript* file to parse and execute
* ``--locale`` (``-l``): specify a keyboard disposition (default: *us*)
* ``--key`` (``-k``): encryption key (in hex) to use for payload injection, enables encryption if set

.. include:: ../generic/debug-options.rst

Logging keyboard keypresses
---------------------------

If ``wuni-keyboard`` is simply executed against a wireless Logitech Unifying keyboard,
it synchronizes with this keyboard and logs every keypresses sent
by the device to its associated dongle.

If the connection between the target keyboard and its dongle is encrypted, a key
must be provided with the ``--key`` option to allow ``wuni-keyboard`` to decrypt
the exchanged data. If no key is provided, this tool will not be able to capture
any keypress.

Sending unencrypted keypresses
------------------------------

``wuni-keyboard`` is also able to send unencrypted keypresses to various Logitech
Unifying keyboard dongles, even those using encryption thanks to a vulnerability
identified and documented by Marc Newlin (*MouseJack*).

The ``--payload`` option can be used to define a text payload that will be send
to the target dongle (followed by a press on *ENTER*):

.. code-block:: text

    $ wuni-keyboard -i uart0 -a 99:f9:51:2e:a4 -p "Hello world !"

A better way to specify a payload or series of keypresses to inject is to write
a *DuckyScript* and provide it to ``wuni-keyboard``:

.. code-block:: text

    $ wuni-keyboard -i uart0 -a 99:f9:51:2e:a4 -d myscript.ducky

``wuni-keyboard`` supports only *DuckyScript* version 1 compatible scripts
(for now).

Last but not least, a text payload can be feed into ``wuni-keyboard`` through
its standard input and then sent to the target Logitech Unifying dongle:

.. code-block:: text

    $ echo "Hello world !" | wuni-keyboard -i uart0 -a 99:f9:51:2e:a4

Sending encrypted keypresses
----------------------------

Specifying an encryption key with ``--key`` enables encryption and will allow
``wuni-keyboard`` to send encrypted keypresses using the ``--payload`` or
``--ducky`` options.

The encryption key must be provided as a 128-bit hex-encoded value:

.. code-block:: text

    $ wuni-keyboard -i uart0 -a 99:f9:51:2e:a4 -d myscript.ducky --key 086712d2f4f567662cb5ebafca20bb96


Using a different keyboard disposition
--------------------------------------

Using the ``--locale`` option, it is possible to send the correct HID key codes
to the target wireless keyboard dongle. The following dispositions are supported:
*be*, *br*, *ca*, *ch*, *de*, *dk*, *es*, *fi*, *fr*, *gb*, *hr*, *it*, *no*,
*pt*, *ru*, *si*, *sv*, *tr*, *us*. The default locale is *us*.


.. warning:: This tool cannot be used in conjunction with ``wserver``, due to extra latency induced by the TCP connection
