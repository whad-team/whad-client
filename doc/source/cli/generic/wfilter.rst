.. _generic-tools-wfilter:

wfilter: generic packet filtering and processing tool
=====================================================

``wfilter`` allows simple packet processing and filtering and is intended to be
used chained with other WHAD tools. This tool can alter packets coming from the
previous tool in the processing chain to the next tool (upstream) or the other way
(downstream).

Usage
-----

.. code-block:: text

    ... | wfilter [OPTIONS] FILTER | ...

Command-line options
^^^^^^^^^^^^^^^^^^^^

**wplay** supports the following options:

* ``--down``: process downstream packets
* ``--up``: process upstream packets
* ``--transform`` (``-t``): apply a transform to packets
* ``--invert`` (``-e``): invert filter
* ``--forward`` (``-f``): forward packets that do not match the specified filter (dropped by default)
* ``--load`` (``-l``): load specified Python module containing extra Scapy layers definitions

Specifying a filter
^^^^^^^^^^^^^^^^^^^

``wfilter`` relies on a filter to process the flow of packets going through the
packet processing chain, this filter is defined as a Python expression that must
return a boolean value. The packet is available in this expression as ``p`` (also
as ``pkt`` or ``packet`` for readability) and is a *Scapy* packet object.

For instance, specifying the filter ``BTLE_ADV_IND in p`` will specify a filter
that would match any packet that contains the ``BTLE_ADV_IND`` layer (Bluetooth
Low Energy indirected advertisement in this specific case).

Inverting filter
^^^^^^^^^^^^^^^^

The ``--invert / -e`` option will invert the filter expression.

Specifying additional Scapy layers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``--load / -l`` option can be used to specify a Python module containing
additional Scapy layers definitions to load. This can come handy when working
on non-standard protocols for which Scapy does not have any layer defined.

This option can be used more than once to load as many Python module as necessary.


Applying a transform to matching packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``--transform / -t`` option can be used to transform a packet that matches
the provided filter, combined with ``--up`` or ``--down`` to specify which packets
need to be processed. ``--up`` will tell ``wfilter`` to process upstream packets,
that is packets sent by the previous tool in the processing chain to the next tool
while ``--down`` will apply this transform to downstream packets coming from the
next tool to the previous tool in the chain. If both ``--up`` and ``--down`` are
specified, transform will be applied to upstream and downstream packets.

The transform must be specified as a Python expression altering the packet,
refered as ``p`` in the transform expression.

.. note::

    Non-matching packets will not be forwarded as dropped by default by the specified filter.

Applying a transform to matching packets and forwarding other packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``--forward / -f`` option tells ``wfilter`` to apply the specified transform
to packets that match the provided filter expression, as detailed above, but
also to forward other packets without applying any transform instead of just
dropping them.

Therefore, combining ``--transform`` with ``--forward`` allow to apply a specific
transform on some packets while keeping the others untouched.


Simple packet filtering
-----------------------

As a first example, we are going to filter BLE packets to only keep BLE advertisements
from a specific advertising device (*cc:5f:f0:e5:81:75*):

.. code-block:: text

    $ wplay --flush ressources/pcaps/ble_discovery.pcap ble | wfilter "BTLE_ADV_IND in p and p.AdvA == 'cc:5f:f0:e5:81:75'"
    [ raw=True, decrypted=False, timestamp=0, channel=0, rssi=-50, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    <BTLE  access_addr=0x8e89bed6 crc=0x0 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=#2 RFU=0 PDU_type=ADV_IND Length=0x25 |<BTLE_ADV_IND  AdvA=cc:5f:f0:e5:81:75 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode+br_edr_not_supported |>>, <EIR_Hdr  len=17 type=complete_list_128_bit_svc_uuids |<EIR_CompleteList128BitServiceUUIDs  svc_uuids=[UUID('bdce0001-e90d-4685-b89d-5578cd199a9f')] |>>, <EIR_Hdr  len=9 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0xffff |<Raw  load='u\\x81\\xe5\\xf0_\\xcc' |>>>] |>>>

    [ raw=True, decrypted=False, timestamp=86188, channel=0, rssi=-50, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    <BTLE  access_addr=0x8e89bed6 crc=0x0 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=#2 RFU=0 PDU_type=ADV_IND Length=0x25 |<BTLE_ADV_IND  AdvA=cc:5f:f0:e5:81:75 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode+br_edr_not_supported |>>, <EIR_Hdr  len=17 type=complete_list_128_bit_svc_uuids |<EIR_CompleteList128BitServiceUUIDs  svc_uuids=[UUID('bdce0001-e90d-4685-b89d-5578cd199a9f')] |>>, <EIR_Hdr  len=9 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0xffff |<Raw  load='u\\x81\\xe5\\xf0_\\xcc' |>>>] |>>>

Simple packet processing
------------------------

Next, we are going to modify the received signal strength of all packets to -20:

.. code-block:: text

    $ wplay --flush ressources/pcaps/ble_discovery.pcap ble | wfilter -t "p.metadata.rssi=-20" --down
    [ raw=True, decrypted=False, timestamp=0, channel=0, rssi=-20, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    <BTLE  access_addr=0x8e89bed6 crc=0x0 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=#2 RFU=0 PDU_type=ADV_IND Length=0x25 |<BTLE_ADV_IND  AdvA=cc:5f:f0:e5:81:75 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode+br_edr_not_supported |>>, <EIR_Hdr  len=17 type=complete_list_128_bit_svc_uuids |<EIR_CompleteList128BitServiceUUIDs  svc_uuids=[UUID('bdce0001-e90d-4685-b89d-5578cd199a9f')] |>>, <EIR_Hdr  len=9 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0xffff |<Raw  load='u\\x81\\xe5\\xf0_\\xcc' |>>>] |>>>

    [ raw=True, decrypted=False, timestamp=86188, channel=0, rssi=-20, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    <BTLE  access_addr=0x8e89bed6 crc=0x0 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=#2 RFU=0 PDU_type=ADV_IND Length=0x25 |<BTLE_ADV_IND  AdvA=cc:5f:f0:e5:81:75 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode+br_edr_not_supported |>>, <EIR_Hdr  len=17 type=complete_list_128_bit_svc_uuids |<EIR_CompleteList128BitServiceUUIDs  svc_uuids=[UUID('bdce0001-e90d-4685-b89d-5578cd199a9f')] |>>, <EIR_Hdr  len=9 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0xffff |<Raw  load='u\\x81\\xe5\\xf0_\\xcc' |>>>] |>>>

Or we also can change the advertiser address to *11:22:33:44:55:66* for every ``BTLE_ADV_IND`` packet:

.. code-block:: text

    $ wplay --flush ressources/pcaps/ble_discovery.pcap ble | wfilter -t "p[BTLE_ADV_IND].AdvA='11:22:33:44:55:66'" --down "BTLE_ADV_IND in p"
    [ raw=True, decrypted=False, timestamp=0, channel=0, rssi=-50, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    <BTLE  access_addr=0x8e89bed6 crc=0x0 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=#2 RFU=0 PDU_type=ADV_IND Length=0x25 |<BTLE_ADV_IND  AdvA=11:22:33:44:55:66 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode+br_edr_not_supported |>>, <EIR_Hdr  len=17 type=complete_list_128_bit_svc_uuids |<EIR_CompleteList128BitServiceUUIDs  svc_uuids=[UUID('bdce0001-e90d-4685-b89d-5578cd199a9f')] |>>, <EIR_Hdr  len=9 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0xffff |<Raw  load='u\\x81\\xe5\\xf0_\\xcc' |>>>] |>>>

    [ raw=True, decrypted=False, timestamp=86188, channel=0, rssi=-50, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, processed=False, encrypt=False ]
    <BTLE  access_addr=0x8e89bed6 crc=0x0 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=#2 RFU=0 PDU_type=ADV_IND Length=0x25 |<BTLE_ADV_IND  AdvA=11:22:33:44:55:66 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode+br_edr_not_supported |>>, <EIR_Hdr  len=17 type=complete_list_128_bit_svc_uuids |<EIR_CompleteList128BitServiceUUIDs  svc_uuids=[UUID('bdce0001-e90d-4685-b89d-5578cd199a9f')] |>>, <EIR_Hdr  len=9 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0xffff |<Raw  load='u\\x81\\xe5\\xf0_\\xcc' |>>>] |>>>

