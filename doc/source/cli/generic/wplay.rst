wplay: WHAD generic replay tool
===============================

``wplay`` is a simple tool that replays packets from a PCAP file and send them
to a piped WHAD tool. It allows PCAP post-processing, data extraction or simple
communication replay.

This tool MUST be chained with at least another WHAD CLI tool.

Usage
-----

.. code-block:: text

    wplay PCAP DOMAIN [DOMAIN OPTIONS] | ...

Command-line options
^^^^^^^^^^^^^^^^^^^^

**wplay** supports the following options:

* ``--no-metadata``: hide packets metadata
* ``--format``: specify the output format (`raw`, `hexdump`, `show`, `repr`)
* ``--output`` (``-o``): specifies a target PCAP file in which all captured data will be saved
* ``--wireshark`` (``-w``): spawns a wireshark instance that will monitor packets in real-time
* ``--flush``: enable wireshark monitoring

How to replay a PCAP file with ``wplay``
----------------------------------------

It is a child's play, the following example will replay the BLE packets from the specified
PCAP file `ble_discovery.pcap` and feed them into ``wfilter`` in order to only keep the
captured advertisements:

.. code-block:: text

    $ wplay --flush --format=hexdump resources/pcaps/ble_discovery.pcap ble | wfilter 'BTLE_ADV_IND in p'
    [ raw=True, decrypted=False, timestamp=0, channel=0, rssi=-50, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    00000000: D6 BE 89 8E 20 25 75 81  E5 F0 5F CC 02 01 06 11  .... %u..._.....
    00000010: 07 9F 9A 19 CD 78 55 9D  B8 85 46 0D E9 01 00 CE  .....xU...F.....
    00000020: BD 09 FF FF FF 75 81 E5  F0 5F CC 00 00 00        .....u..._....

    [ raw=True, decrypted=False, timestamp=86188, channel=0, rssi=-50, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    00000000: D6 BE 89 8E 20 25 75 81  E5 F0 5F CC 02 01 06 11  .... %u..._.....
    00000010: 07 9F 9A 19 CD 78 55 9D  B8 85 46 0D E9 01 00 CE  .....xU...F.....
    00000020: BD 09 FF FF FF 75 81 E5  F0 5F CC 00 00 00        .....u..._....

The ``--flush`` option will send all the packets from the source PCAP file at once. Without this option,
packets are replayed following their respective timestamps, as the same pace they were captured. This could
be useful to replay a communication at the same speed as the original, or almost the same speed since WHAD
will add a small extra latency due to its processing.
