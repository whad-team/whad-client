wextract: generic data extraction tool
======================================

``wextract`` allows data extraction and formatting from packets captured from sniffing or through
PCAP replay. It is intended to be used chained with other WHAD tools.

Usage
-----

.. code-block:: text

    ... | wextract [OPTIONS] EXTRACTOR | ...

``wextract`` expects a series of expression EXTRACTOR that is some Python code that will be run to extract
and format data for each packet that goes through the WHAD processing chain.

Command-line options
^^^^^^^^^^^^^^^^^^^^

**wextract** supports the following options:

* ``-d``: set delimiter for extraction
* ``--exceptions`` (``-x``): enable verbose output on exceptions for debugging 
* ``--load`` (``-l``): load specified Python module containing extra Scapy layers definitions


Writing extractors
^^^^^^^^^^^^^^^^^^

Each parameter passed to ``wextract`` is considered as a Python expression that
retrieves a specific information for each packet processed, available in the ``p``
variable when extraction expressions are evaluated. ``p`` is an instance of a *Scapy*
packet and therefore allows to access all layers and fields as defined in *Scapy*.

A delimiter can be set with ``-d`` that will be used to delimit data from each
extractor. By default, a white space will be used.

If an invalid extraction expression is passed or if an extractor raises an exception,
an error message is shown on *stderr*.

Extracting data from packets
----------------------------

For instance, we can extract the advertised BD address from sniffed Bluetooth Low Energy
advertisements and their associated signal strength:

.. code-block:: text

    $ wsniff -i uart0 ble -a | wextract -d ',' "p.AdvA" "p.metadata.rssi"
    a4:c1:38:60:fc:5c,-69
    6b:37:c6:f1:89:ae,-74
    d0:d0:03:77:53:28,-70
    a4:c1:38:60:fc:5c,-69
    d0:d0:03:77:53:28,-70

In this case, we access the Bluetooth Low Energy advertisement's advertiser address
field (``AdvA``) as defined in *Scapy*'s ``BTLE_ADV_IND`` layer for instance but also
the packet metadata that contains the received signal strength. This metadata is
automatically added by WHAD and is made available to any tool. The delimiter ``,`` is
set through the ``-d`` option.