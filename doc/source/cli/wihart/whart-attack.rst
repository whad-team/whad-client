whart-attack: WirelessHART attacking tool
====================================================
.. _whart-attack:

``whart-attack`` operates in two different motes depending on how you launch it :

* **Chained mode**: when piped in after :ref:`whart-sync <whart-sync>` it receives the synchronized interface and runs single attacks selected through the options.
* **Interactive mode**: when runned on its own with a specified WHAD interface it is able to opens an interactive shell and is able to synchronize, sniff and inject traffic.

.. contents:: Table of Contents
    :local:
    :depth: 3

Usage 
-----


.. code-block:: text

    whart-sync [OPTIONS] | whart-attack <ATTACK> [ARGS]         (chained mode)
    whart-attack -i <interface> -c <channel> [options]          (interactive mode)



Chained mode 
------------

The attacks in this mode are selected as the first argument and are one-time runned. 
Each attack has its own options : 

adv
~~~

.. code-block:: text

    whart-attack adv --dst <address> [--wait <offset (µs)>]


Injects a fake advertisement toward the given node.
* ``--dst``: target node address (required)
* ``--wait``: wait offset from the start of the slot, in microseconds (default 1000)

ka
~~~

.. code-block:: text

    whart-attack ka --dst <node> [--wait <offset (µs)>]

Injects a fake keep-alive toward the given node.

* ``--dst``: target node address (required)
* ``--wait``: wait offset from the start of the slot, in microseconds (default 1000)


ping
~~~~

.. code-block:: text

    whart-attack ping --dst <node> [--graph <id>]

Injects a fake ping request toward the given node.

* ``--dst``: target node address (required)
* ``--graph``: graph id to use (default 1)


deauth
~~~~~~

.. code-block:: text

    whart-attack deauth --dst <node> [--duration <slots>]

Injects a suspend command (mass de-authentication) toward the given node.

* ``--dst``: target node address (required)
* ``--duration``: suspend duration in number of slots while suspended (default 1000)

Chained-mode example
-----

.. code-block:: text

    $ whart-sync -i uart0 -d -j 445553544E4554574F524B53524F434B -m 6 | whart-attack adv --dst 6

Interactive mode
---------------

When launched on its own cith an interface the tool opens an interactive shell. A status bar at the bottow shows informations related to the network or the tool
such as the synchronization state, the current ASN the last time offset (reception timestamp - start of slot timestamp)...

Command-line options
~~~~~~~~~~~~~~~~~~~~

* ``--interface`` (``-i``): specifies the WHAD interface to use
* ``--channel`` (``-c``): channel to synchronize on (required in interactive mode)
* ``--join-key`` (``-j``): join key (hex)
* ``--decrypt`` (``-d``): try to decrypt packets

.. include:: ../generic/debug-options.rst

Start the shell
~~~~~~~~~~~~~~~~~~

.. code-block:: text

    $ whart-attack -i uart0 -c 11
    [*] Listening on channel 11
    PROMPT THREAD ALIVE

    [+] Interactive mode ready. Type 'help' for commands.
    whart>

Supported commands
~~~~~~~~~~~~~~~~~~~

The shell provides autocompletion. The following commands are available:

help
""""

Shows available commands.

sync
""""

Shows the synchronization state, and synchronized by scanning an active channel if not yet synchronized.


join-key
""""""""

Prompts for a join key (hex) and stores it.

keys
""""

Prints the key stored currently.

show-packets
""""""""""""

Toggles the display of received packets.


decrypt
"""""""

Enables decryption of received traffic.

ping
""""

Injects a ping request. Prompts for the target node, the graph id and the wait offset.

adv
"""

Injects a fake advertisement. Prompts for the target node and the wait offset.

ka
"""

Injects a keep-alive. Prompts for the target node.


deauth
""""""

Injects a suspend command. Prompts for the target node and the suspend duration.

save
""""

Saves the current network state to a file (prompts for the file name).


exit / quit
"""""""""""

Leaves the shell.


.. note::

    For injectiopn the tool still needs a valid link toward ``--dst`` to pick the transmission slot.
    Use a node address for which the captured schedule holds a broadcast link.