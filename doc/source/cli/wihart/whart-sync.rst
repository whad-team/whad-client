whart-sync: WirelessHART synchronizing tool
====================================================
.. _whart-sync:
``whart-sync`` synchronizes a WHAD interface to a WirelessHART network. It is able to capture the 
cryptographic material required to interact with the network if option -d/--decrypt specified. 
This tool hands the interface over a chained tool (typically :ref:`whart-attack <whart-attack>`) through a Unix socket.


Usage
-----

.. code-block:: text

    whart-sync [OPTIONS] | <chained-whad-tool> [TOOL OPTIONS]


``whart-sync`` accepts one or more options. 

Once synchronized, it keeps the interface open and bridges it to the next tool in the pipe.

Command-line options
--------------------

**whart-sync** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use
* ``--channel`` (``-c``): channel to listen on to synchronize. If not specified, the tool will scan the different channels looking for an active one.
* ``--decrypt`` (``-d``); decrypt communications and only hand over the interface when the keys have been captured
* ``--join-key`` (``-j``): join key (hex) used to decrypt the join requests sent by joining motes
* ``--mote`` (``-m``): address of a mote joining the network. When set, the tool waits until the unicast session keys of this mote have been captured
* ``--show-packets`` (``-s``): show packets received during synchronization
* ``--hide-advertisement`` (``-ha``): hide advertisement packets when showing

.. include:: ../generic/debug-options.rst



Examples
--------

Synchronize with the network after looking for an active channel, wait for the mote 6 until it joins the network and recover its keys then hand over 
the interface to ``whart-attack`` to inject a fake advertisement toward mote ``6``:

.. code-block:: text

    $ whart-sync -i uart0 -d -j 445553544E4554574F524B53524F434B -m 6 | whart-attack adv --dst 6


Notes
-----

.. warning::

    ``whart-sync`` only works when piped into another WHAD tool. Running it on its
    own will produce an error, as it has no standalone output.

.. note::

    When ``--mote`` is set, ``whart-sync`` waits for that mote's unicast session
    keys, which are only exchanged while the mote joins. If the mote has
    already joined, these keys may never be observed during the capture.