winject: generic injection tool
================================

``winject`` is a convenient tool to inject arbitrary data using various wireless protocols or
wireless modulations. It supports any domain natively supported by WHAD and is able to inject
arbitrary data in various formats:

- PHY (raw demodulation)
- Bluetooth Low Energy
- IEEE 802.15.4
- Nordic Semiconductor's *Enhanced ShockBurst* (ESB)
- Logitech's Unifying protocol

Moreover, ``winject`` can be chained with other tools like ``wsniff`` or ``wplay``
to allow more complex data processing.

Usage
-----

.. code-block:: text

    winject [OPTIONS] DOMAIN [DOMAIN OPTIONS] [PACKETS]


Command-line options
^^^^^^^^^^^^^^^^^^^^

**winject** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use to connect to the target device
* ``--repeat`` (``-r``): repeat the transmission of packets
* ``--delay DELAY`` (``-d DELAY``): delay between the transmission of two consecutive packets

Specific PHY options
^^^^^^^^^^^^^^^^^^^^

* ``--frequency`` (``-f``): specifies the target frequency in Hz. This frequency must be in the device' supported frequencies range.
* ``--little-endian`` (``-le``): will interpret bytes as little-endian (LSB first, default is *big-endian*).
* ``--datarate`` (``-d``): set the data rate in number of bits per second (*bps*).
* ``--packet-size`` (``-s``): set the maximum packet (or reception buffer) size in bytes.
* ``--sync-word`` (``-w``): set a synchronization word (hex value expected)
* ``--ask`` (``-ask``): select ASK (Amplitude Shift Keying) modulation
* ``--gfsk`` (``-gfsk``): select GFSK (Gaussian Frequency Shift Keying) modulation
* ``--bfsk`` (``-bfsk``): select BFSK (Binary Frequency Shift Keying) modulation
* ``--qfsk`` (``-qfsk``): select QFSK (Quaternary Frequency Shift Keying) modulation
* ``--bpsk`` (``-bfsk``): select BPSK (Binary Phase Shift Keying) modulation
* ``--qpsk`` (``-qpsk``): select QPSK (Quadrature Phase Shift Keying) modulation
* ``--lora`` (``-lora``): select LoRa (Semtech Long Range) modulation

Specific FSK options
^^^^^^^^^^^^^^^^^^^^

* ``--deviation`` (``-dev``): frequency deviation in Hz

Specific LoRa options
^^^^^^^^^^^^^^^^^^^^^

* ``--spreading-factor`` (``-sf``): set LoRa spreading factor
* ``--coding-rate`` (``-cr``): set LoRa coding rate

  - ``44`` for 4/4
  - ``45`` for 4/5
  - ``46`` for 4/6
  - ``47`` for 4/7
  - ``48`` for 4/8

* ``--bandwidth`` (``-bw``): set LoRa bandwidth in Hz
* ``--enable-crc`` (``-crc``): enable LoRa CRC
* ``--enable-explicit_mode`` (``-em``): enable explicit mode

Specific BLE options
^^^^^^^^^^^^^^^^^^^^

* ``--raw``: inject a packet directly
* ``--inject-to-slave``: inject a packet to slave in a synchronized connection
* ``--inject-to-master``: inject a packet to master in a synchronized connection
* ``--synchronize`` (``-s``): synchronize with a connection before injection
* ``--access-address`` (``-aa``): set the access address corresponding to a connection to target
* ``--crc-init`` (``-crc``): set target connection CRC initial value
* ``--hop-interval`` (``-int``): set target connection hop interval
* ``--hop-increment`` (``-inc``): set target connection hop increment (CSA #1 only)
* ``--channel-map`` (``-chm``): set channel map for the target connection
* ``--channel`` (``-c``): select the channel to use for injection
* ``--filter`` (``-f``): use the provided BD address for injection


Specific ESB options
^^^^^^^^^^^^^^^^^^^^

* ``--channel`` (``-c``): select a channel (0-100) to use for injection
* ``--address`` (``-f``): set a device address to use
* ``--scanning`` (``-s``): scan channels before injecting ESB packets

Specific Logitech Unifying options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``--channel`` (``-c``): select a channel (0-100) to use for injection
* ``--address`` (``-f``): set a device address to use
* ``--scanning`` (``-s``): scan channels before injecting Unifying packets


Specific 802.15.4 options
^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``--channel`` (``-c``): select a channel (11-26) to use for injection


Specific ZigBee options
^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``--channel`` (``-c``): select a channel (11-26) to use for injection


Specific RF4CE options
^^^^^^^^^^^^^^^^^^^^^^^

* ``--channel`` (``-c``): select a channel (11-26) to use for injection


Injecting scapy packets
^^^^^^^^^^^^^^^^^^^^^^^^

``winject`` can use a WHAD-compatible device to inject arbitrary scapy packets.
You can provide the configuration of a specific domain, and append a list of scapy packets afterwards.

For example, the following command will build and inject a Logitech Unifying Mouse packet on the channel 62, using address "ca:e9:06:ec:a4":

.. code-block:: text

    winject -i uart0 unifying -c 62 -f ca:e9:06:ec:a4  \
    "ESB_Hdr(address='ca:e9:06:ec:a4')/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Mouse_Payload(button_mask=0x02)"

Injected on the right channel with the right address, such injection should trigger a right click on the computer connected with the Unifying dongle.

You can also provide multiple packets:

.. code-block:: text

    winject -i uart0 unifying -c 71 -f ca:e9:06:ec:a4 \
    "ESB_Hdr(address='ca:e9:06:ec:a4')/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Unencrypted_Keystroke_Payload(hid_data=bytes.fromhex('001400000000000000'))" \
    "ESB_Hdr(address='ca:e9:06:ec:a4')/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Unencrypted_Keystroke_Payload(hid_data=bytes.fromhex('000000000000000000'))"

If successful, this injection will inject an 'A' keypress then a key release on the computer connected with the Unifying dongle.

Injecting raw buffers
^^^^^^^^^^^^^^^^^^^^^^

``winject`` can also be used to inject arbitrary raw buffers, if the packets are provided as bytestrings.
For example, you can inject an OOK-modulated packet using a Yard Stick One on frequency 433.92MHz using a datarate of 10000 bauds:


.. code-block:: text

    winject -i yardstickone0 phy -f 433920000 -d 10000 --ask \
    fff03e0003fff81fffc1f0000f80007fff07e0003e0001f0000f8000ff

Injecting from a PCAP file
^^^^^^^^^^^^^^^^^^^^^^^^^^^

``winject`` allow to use the output of an other tool, such as ``wplay`` which replays an existing PCAP file, as a source for traffic to inject.
This feature allows to easily implement a replay attack using only command line tools.

For example, let's implement a basic Logitech Unifying replay attack. Let's start by capturing some mouse packets from a Logitech Unifying mouse and dump them into a PCAP file:

.. code-block:: text

    wsniff -i uart0 unifying -s -f ca:e9:06:ec:a4 | wdump /tmp/mouse.pcap

Once packets have been captured, we can easily replay them from the PCAP file and inject them using the following command:

.. code-block:: text

    wplay /tmp/mouse.pcap | winject -i uart0 -s -f ca:e9:06:ec:a4

.. warning::

    Note that in the previous example, the domain (unifying) is not provided to winject nor wplay.
    This feature relies on the fact that by default, every PCAP captured by WHAD has its header patched to remember the corresponding domain.
    While this feature is convenient, note that any unpatched PCAP file (for example, if captured from another tool) will need to explicitely provide a domain after the PCAP filename.
    You can also force the interpretation of traffic as a specific domain by providing the domain explicitely in winject.




Bluetooth Low Energy injection
-------------------------------

``winject`` provides specific features for injecting Bluetooth Low Energy packets:

* injecting raw packets directly on a specific channel (can be used to replay advertisements)
* injecting packets to Peripheral (Slave) in an existing connection, using InjectaBLE attack
* injecting packets to Central (Master) in an existing connection, using InjectaBLE attack


Injecting raw advertisements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``winject`` provides the ``--raw`` option, allowing to inject a packet directly on a given channel.
This feature can be used to inject BLE advertisements. In this example, we transmit a BLE advertisement repeatedly every 0.05s on channel 37:

.. code-block:: text

    $ winject -r -d 0.05 -i uart0 ble --raw -c 37 d6be898e022228537703d0d01bff75004204018060d0d003775328d2d0037753270100000000000005da96

    [!] Transmitting:

    <BTLE  access_addr=0x8e89bed6 crc=0x5da96 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=0 RFU=0 PDU_type=ADV_NONCONN_IND Length=0x22 |<BTLE_ADV_NONCONN_IND  AdvA=d0:d0:03:77:53:28 data=[<EIR_Hdr  len=27 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0x75 |<Raw  load="B\x04\x01\\x80`\\xd0\\xd0\x03wS(\\xd2\\xd0\x03wS'\x01\x00\x00\x00\x00\x00\x00" |>>>] |>>>

Replaying advertisements from a PCAP file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can also clone advertisements extracted from a PCAP file. Let's start by sniffing some BLE advertisements with ``wsniff`` while capturing them in a PCAP file:

.. code-block:: text

    $ wsniff -o /tmp/advertisements.pcap -i uart0 ble -a
    [ raw=True, decrypted=False, timestamp=316370100, channel=37, rssi=-74, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0x45c882 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=0 RFU=0 PDU_type=ADV_IND Length=0x1c |<BTLE_ADV_IND  AdvA=11:75:58:2a:f3:28 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode |>>, <EIR_Hdr  len=18 type=complete_local_name |<EIR_CompleteLocalName  local_name='TimeBox-Evo-audio' |>>] |>>>

    [ raw=True, decrypted=False, timestamp=316375426, channel=37, rssi=-83, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0x273963 |<BTLE_ADV  RxAdd=public TxAdd=random ChSel=0 RFU=0 PDU_type=ADV_IND Length=0x24 |<BTLE_ADV_IND  AdvA=d4:a0:9e:35:57:a4 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode+br_edr_not_supported |>>, <EIR_Hdr  len=17 type=incomplete_list_128_bit_svc_uuids |<EIR_IncompleteList128BitServiceUUIDs  svc_uuids=[UUID('496e0040-0000-696f-6e01-000000000000')] |>>, <EIR_Hdr  len=8 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0x59 |<Raw  load='\x00S\\x8a\x12\x01' |>>>] |>>>

    [ raw=True, decrypted=False, timestamp=316402700, channel=37, rssi=-85, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0x267c88 |<BTLE_ADV  RxAdd=public TxAdd=random ChSel=0 RFU=0 PDU_type=ADV_NONCONN_IND Length=0x25 |<BTLE_ADV_NONCONN_IND  AdvA=7b:54:84:06:70:45 data=[<EIR_Hdr  len=30 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0x6 |<Raw  load='\x01\t \x02\x038\\x98\\xf4,\\xd1s\\xa6|A#R\\xfce\\x8ad\n\x06\x107ؼ\x0f' |>>>] |>>>

    [ raw=True, decrypted=False, timestamp=316417881, channel=37, rssi=-70, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0x7ff76f |<BTLE_ADV  RxAdd=public TxAdd=random ChSel=0 RFU=0 PDU_type=ADV_NONCONN_IND Length=0x25 |<BTLE_ADV_NONCONN_IND  AdvA=1a:bb:51:e4:70:9d data=[<EIR_Hdr  len=30 type=mfg_specific_data |<EIR_Manufacturer_Specific_Data  company_id=0x6 |<Raw  load='\x01\t "5\\xa9wp)\\xe3\\xf9\\xa6\\x9c!!:\\xd1E\\xc3#(\\x95\x13\\xd26f\\x9e' |>>>] |>>>

    [...]


Let's replay the device with BD address *'11:75:58:2a:f3:28'*, named *'TimeBox-Evo-audio'*. We will generate a pipeline of commands to perform the following actions:

  * ``wplay /tmp/advertisements.pcap``: Replay the content of the PCAP file /tmp/advertisements.pcap
  * ``wfilter "p.AdvA == '11:75:58:2a:f3:28'"``: Apply a filter to keep only traffic from the target device
  * ``-t "p.AdvA='11:22:33:44:55:66'"``: Apply a transformation to filtered packets to replace BD address by *'11:22:33:44:55:66'*
  * ``winject -r -d 0.01 -i uart0 --raw -c 37``: Inject the raw packets directly and repeatedly, every 0.01s on channel 37

The final command is:

.. code-block:: text

    $ wplay /tmp/advertisements.pcap | \                                                                                                                                               ST 27   main 
    wfilter "p.AdvA == '11:75:58:2a:f3:28'" -t "p.AdvA='11:22:33:44:55:66'" | \
    winject -r -d 0.01 -i uart0 --raw -c 37

    [!] Transmitting:
    [ raw=True, decrypted=False, timestamp=7366, channel=37, rssi=-74, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0x45c882 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=0 RFU=0 PDU_type=ADV_IND Length=0x1c |<BTLE_ADV_IND  AdvA=11:22:33:44:55:66 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode |>>, <EIR_Hdr  len=18 type=complete_local_name |<EIR_CompleteLocalName  local_name='TimeBox-Evo-audio' |>>] |>>>

    [!] Transmitting:
    [ raw=True, decrypted=False, timestamp=31491, channel=37, rssi=-74, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0x45c882 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=0 RFU=0 PDU_type=ADV_IND Length=0x1c |<BTLE_ADV_IND  AdvA=11:22:33:44:55:66 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode |>>, <EIR_Hdr  len=18 type=complete_local_name |<EIR_CompleteLocalName  local_name='TimeBox-Evo-audio' |>>] |>>>

    [!] Transmitting:
    [ raw=True, decrypted=False, timestamp=55117, channel=37, rssi=-73, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0x45c882 |<BTLE_ADV  RxAdd=public TxAdd=public ChSel=0 RFU=0 PDU_type=ADV_IND Length=0x1c |<BTLE_ADV_IND  AdvA=11:22:33:44:55:66 data=[<EIR_Hdr  len=2 type=flags |<EIR_Flags  flags=general_disc_mode |>>, <EIR_Hdr  len=18 type=complete_local_name |<EIR_CompleteLocalName  local_name='TimeBox-Evo-audio' |>>] |>>>

    [...]

If we perform a BLE scan using another interface, we can observe our spoofed device in the output:

.. code-block:: text

    $ wble-central -i hci0 scan
    RSSI Lvl  Type  BD Address        Extra info
    [ -75 dBm] [RND] 62:94:29:b5:71:2d
    [ -90 dBm] [RND] 5d:c1:f0:56:b7:0a
    [ -77 dBm] [RND] df:de:71:72:db:74 name:"Expert_DFDE7172DB74"
    [ -85 dBm] [RND] 7b:b9:d0:d3:6e:ea name:"LE_WF-C500"
    [ -91 dBm] [RND] 5d:e8:88:36:fe:6d
    [ -43 dBm] [PUB] 11:22:33:44:55:66 name:"TimeBox-Evo-audio"


Injecting packets into an established connection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some devices (mainly ButteRFly) allows to perform a BLE packet injection into an established connection, using InjectaBLE attack.
Before performing the injection, you must synchronize with the connection (``--synchronize`` / ``-s``): ``winject`` will then wait a new connection and synchronize with it before performing the injection.
If needed, you can apply a filter on a specific BD address using ``--filter``/``-m`` option.

If you want to inject a BLE packet to Peripheral (Slave), use option ``--inject-to-slave``:

.. code-block:: text

    winject -i uart0 ble -s -m 11:22:33:44:55:66 --inject-to-slave "BTLE()/BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Read_Request(gatt_handle=0x21)"

You can also inject a BLE packet to Central (Peripheral) using option ``--inject-to-master``:

.. code-block:: text

    winject -i uart0 ble -s -m 11:22:33:44:55:66 --inject-to-master "BTLE()/BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Handle_Value_Notification(gatt_handle=0x21, value=b'\x41\x42\x43')"

802.15.4, ZigBee & RF4CE Injection
------------------------------------

``winject`` allows to easily inject 802.15.4 packets.

The following command will inject a packet using 802.15.4 domain (dot15d4):

.. code-block:: text

    $ winject -i uart0 dot15d4 -c 11 008021f4ec1700ff0f000000228ce33a7768bac3a278ffffff00f4f1                                                                                                 ST 27   main 
    [!] Transmitting:

    <Dot15d4TAP_Hdr  data=[<Dot15d4TAP_TLV_Hdr  type=fcs_type |<Dot15d4TAP_FCS_Type  fcs_type=16-bit CRC |>>] |<Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=False fcf_ackreq=False fcf_pending=False fcf_security=False fcf_frametype=Beacon fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=None fcf_reserved_2=0 seqnum=33 fcs=0xf1f4 |<Dot15d4Beacon  src_panid=0xecf4 src_addr=0x17 sf_sforder=15 sf_beaconorder=15 sf_assocpermit=False sf_pancoord=False sf_reserved=0 sf_battlifeextend=False sf_finalcapslot=15 gts_spec_permit=False gts_spec_reserved=0 gts_spec_desccount=0 pa_reserved_1=0 pa_num_long=0 pa_reserved_2=0 pa_num_short=0 |<ZigBeeBeacon  proto_id=0 nwkc_protocol_version=2 stack_profile=2 end_device_capacity=1 device_depth=1 router_capacity=1 reserved=0 extended_pan_id=78:a2:c3:ba:68:77:3a:e3 tx_offset=16777215 update_id=0 |>>>>

You can check that the packet is correctly transmitted using ``wsniff``:

.. code-block:: text

    $ wsniff -i uart1 zigbee -c 11
    [ decrypted=False, timestamp=3543855, channel=11, rssi=-54, is_fcs_valid=False, lqi=156 ]
    <Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=False fcf_ackreq=False fcf_pending=False fcf_security=False fcf_frametype=Beacon fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=None fcf_reserved_2=0 seqnum=33 fcs=0xf4f1 |<Dot15d4Beacon  src_panid=0xecf4 src_addr=0x17 sf_sforder=15 sf_beaconorder=15 sf_assocpermit=False sf_pancoord=False sf_reserved=0 sf_battlifeextend=False sf_finalcapslot=15 gts_spec_permit=False gts_spec_reserved=0 gts_spec_desccount=0 pa_reserved_1=0 pa_num_long=0 pa_reserved_2=0 pa_num_short=0 |<ZigBeeBeacon  proto_id=0 nwkc_protocol_version=2 stack_profile=2 end_device_capacity=1 device_depth=1 router_capacity=1 reserved=0 extended_pan_id=78:a2:c3:ba:68:77:3a:e3 tx_offset=16777215 update_id=0 |<Raw  load='\\xf4\\xf1' |>>>>

Similarly, you can transmit ZigBee or RF4CE packets using respectively "zigbee" or "rf4ce" instead of dot15d4.

ESB and Unifying Injection
---------------------------

``winject`` allows to easily inject ESB or Logitech Unifying packets.

Injecting a single Unifying packet
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For example, the following command will build and inject a Logitech Unifying Mouse packet on the channel 62, using address "ca:e9:06:ec:a4":

.. code-block:: text

    winject -i uart0 unifying -c 62 -f ca:e9:06:ec:a4  \
    "ESB_Hdr(address='ca:e9:06:ec:a4')/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Mouse_Payload(button_mask=0x02)"

Injected on the right channel with the right address, such injection should trigger a right click on the computer connected with the Unifying dongle.

Injecting multiple Unifying packet
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can also provide multiple packets:

.. code-block:: text

    winject -i uart0 unifying -c 71 -f ca:e9:06:ec:a4 \
    "ESB_Hdr(address='ca:e9:06:ec:a4')/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Unencrypted_Keystroke_Payload(hid_data=bytes.fromhex('001400000000000000'))" \
    "ESB_Hdr(address='ca:e9:06:ec:a4')/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Unencrypted_Keystroke_Payload(hid_data=bytes.fromhex('000000000000000000'))"

If successful, this injection will inject an 'A' keypress then a key release on the computer connected with the Unifying dongle, leveraging MouseJack Unencrypted Keystroke injection.


Replaying a sniffed Unifying communication
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's start by capturing some mouse packets from a Logitech Unifying mouse while moving the mouse and dump them into a PCAP file:

.. code-block:: text

    wsniff -i uart0 unifying -s -f ca:e9:06:ec:a4 | wdump /tmp/mouse.pcap

Once the packet have been captured, we can easily replay them from the PCAP file and inject them using the following command:

.. code-block:: text

    wplay /tmp/mouse.pcap | winject -i uart0 -s -f ca:e9:06:ec:a4

If everything works properly, you should see the captured mouse movement reproduced on your screen.

Injecting raw ESB packet
^^^^^^^^^^^^^^^^^^^^^^^^^

You can inject raw packets directly. For example, the following command will inject a raw ESB Ping Request for device *'11:22:33:44:55'* on channel 15:

.. code-block:: text

    $ winject -i uart0 esb -c 15 -f 11:22:33:44:55 "ESB_Hdr(address='11:22:33:44:55')/ESB_Payload_Hdr()/ESB_Ping_Request()"                                                                  ST 27   main 
    [!] Transmitting:

    <ESB_Hdr  address=11:22:33:44:55 |<ESB_Payload_Hdr  |<ESB_Ping_Request  |>>>

You can monitor that the packet has been correctly transmitted using ``wsniff`` and another device:

.. code-block:: text

    $ wsniff -i uart1 esb -c 15 -f 11:22:33:44:55

    [ raw=True, decrypted=False, timestamp=3803020, channel=15, rssi=-17, is_crc_valid=True, address=11:22:33:44:55 ]
    <ESB_Hdr  preamble=0xaa address_length=5 address=11:22:33:44:55 payload_length=4 pid=0 no_ack=0 padding=0 valid_crc=yes crc=0xb555 |<ESB_Payload_Hdr  |<ESB_Ping_Request  ping_payload='\x0f\x0f\x0f\x0f' |>>>


Injecting arbitrary modulated data
------------------------------------

Using "phy" domain, it's possible to inject arbitrary data and use a dedicated modulation to transmit them.

Injecting arbitrary data
^^^^^^^^^^^^^^^^^^^^^^^^^

For example, you can inject an OOK-modulated packet using a Yard Stick One on frequency 433.92MHz using a datarate of 10000 bauds:

.. code-block:: text

    winject -i yardstickone0 phy -f 433920000 -d 10000 --ask \
    fff03e0003fff81fffc1f0000f80007fff07e0003e0001f0000f8000ff

Replaying an On-Off-Keying signal from a wireless doorbell
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Let's consider a simple replay attach, where we sniff a simple signal allowing to activate a wireless doorbell operating at 433.92MHz.

First, let's sniff the signal using ``wsniff`` and record it in a PCAP file using ``wdump``:

.. code-block:: text

    $ wsniff -i yardstickone0 phy -f 433920000 -d 10000 --ask | wdump /tmp/doorbell.pcap
    32 packets have been dumped into /tmp/doorbell.pcap
    /!\ sniffer stopped (CTRL-C)

Then, let's replay the PCAP file using ``wplay`` and inject the recorded signal using the same parameters using ``winject``:

.. code-block:: text

    $ wplay /tmp/doorbell.pcap | winject -i yardstickone0
    [!] Transmitting:
    [ raw=False, timestamp=96113, rssi=0, frequency=433919677, iq=[], endianness=BIG, deviation=16113, datarate=10002, modulation=ASK, syncword= ]
    <Phy_Packet  data=f000000000000000000000000002ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff |>

    [!] Transmitting:
    [ raw=False, timestamp=112135, rssi=0, frequency=433919677, iq=[], endianness=BIG, deviation=16113, datarate=10002, modulation=ASK, syncword= ]
    <Phy_Packet  data=f000000000000000000000000000c3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe |>

    [!] Transmitting:
    [ raw=False, timestamp=128180, rssi=0, frequency=433919677, iq=[], endianness=BIG, deviation=16113, datarate=10002, modulation=ASK, syncword= ]
    <Phy_Packet  data=ff80007c0007e0003e0001fffc1f8000f80007fff07e0003f0001fffe0f80007fff07fff83fffc1fffe0ffff07c0007fff83f0001fffe0f80007fff07fff83e0001f0000fffe0f80007c0003fff83fffc1f0000000000000000007fff83e0001f0001f8000f80007fff07e0003f0001fffe0f80007c0007fff83f0001fffe0ffff07fff07fff83fffc1f0000fffe0f80007fff87e0003fffc1fffe0f8000fc0007fff83e0001f0001fffe0ffff07c000000000000000001fffc1f0000f80007c0007e0003fffc1f0 |>

    [!] Transmitting:
    [ raw=False, timestamp=144230, rssi=0, frequency=433919677, iq=[], endianness=BIG, deviation=16113, datarate=10002, modulation=ASK, syncword= ]
    <Phy_Packet  data=f80f80007fff07c0003e0001fffc1f0000fffe0ffff07fff83fffc1fffc1f0000fffe0fc0007fff83e0003fffc1fffe0f8000fc0007fff83e0001f0001fffe0ffff07c000000000000000001fffc0f8000fc0007c0003e0003fffc1f0000f8000ffff07c0003e0003fffc1f0000fffe0ffff07fff83fffc3fffc1f0000fffe0fc0007fff87e0003fffc1fffe0f80007c0007fff83e0001f0001fffe0ffff07c000000000000000001fffc1f8000f8000fc0007e0003fffc1f0001f8000ffff07c0003e0003fffc1f |>

    [!] Transmitting:
    [ raw=False, timestamp=160268, rssi=0, frequency=433919677, iq=[], endianness=BIG, deviation=16113, datarate=10002, modulation=ASK, syncword= ]
    <Phy_Packet  data=f800ffff07fff07fff83fffc1fffc1f8000ffff07c0007fff83e0001fffc1fffe0f80007c0007fff83e0001f0001fffe0ffff07c000000000000000001fffc1f0000f8000fc0007e0003fffc1f0000f8000ffff07c0003e0003fffc1f0000fffe0ffff07fff87fff83fffc1f0001fffe0f80007fff07e0003fffc1fffe0f8000fc0007fff83e0001f0001fffe0ffff07c000000000000000001fffc1f0000f8000fc0007e0003fffc1f0001f8000ffff07c0003e0003fffc1f0000fffe07fff07fff83fffc1fffe1 |>
