wdump: generic dump tool
========================

``wdump`` is a simple tool that saves packets into a PCAP file.
This tool MUST be used at the end of a processing chain to log packets into
a PCAP file.

Usage
-----

.. code-block:: text

    ... | wdump [OPTIONS] PCAP

Command-line options
^^^^^^^^^^^^^^^^^^^^

**wdump** supports the following options:

* ``--force`` (``-f``): force PCAP file overwrite, if destination file already exists
* ``--append`` (``-a``): append packets to an existing file, create new file if it does not exist

.. include:: debug-options.rst

Saving filtered packets into a PCAP file
----------------------------------------

As a very simple example, the following command uses ``wplay`` (see :ref:`generic-tools-wplay`) and
``wfilter`` (see :ref:`generic-tools-wfilter`) to process a PCAP file, filter packets to only keep BLE
advertisements and save them into a new PCAP file:

.. code-block:: text

    $ wplay --flush ressources/pcaps/ble_discovery.pcap ble | wfilter "BTLE_ADV_IND in p" | wdump ble_advertisements.pcap

