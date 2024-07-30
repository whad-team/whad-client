wsniff: WHAD generic sniffing tool
==================================

``wsniff`` is a convenient tool to sniff data from various wireless protocols or
wireless modulations. It supports any domain natively supported by WHAD and is
able to display the sniffed data in various formats:

- PHY (raw demodulation)
- Bluetooth Low Energy
- IEEE 802.15.4
- Nordic Semiconductor's *Enhanced ShockBurst* (ESB)
- Logitech's Unifying protocol

Moreover, ``wsniff`` can be chained with other tools like ``wextract`` or ``wfilter``
to allow more complex data processing. 

Usage
-----

.. code-block:: text

    wsniff [OPTIONS] DOMAIN [DOMAIN OPTIONS]

Command-line options
^^^^^^^^^^^^^^^^^^^^

**wsniff** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use to connect to the target device
* ``--wireshark`` (``-w``): spawns a wireshark instance that will monitor packets in real-time
* ``--no-metadata``: hide packets metadata
* ``--format``: specify the output format (`raw`, `hexdump`, `show`, `repr`)
* ``--output`` (``-o``): specifies a target PCAP file in which all captured data will be saved

The ``--format`` option tells ``wsniff`` how to display data. By default, captured data is
shown as a series of *Scapy* packets containing raw data. ``raw`` format will display the captured
data as pure hex dump with no interpretation while ``hexdump`` format will show each packet
in hexadecimal with offsets and textual representation. ``show`` format will show capture packets
with all their consecutive layers and fields as produced by *Scapy* packet's ``show()`` method.
``repr`` format will show a packet's Python object representation by calling its ``__repr__()``
method.

Capture raw demodulated data
----------------------------

``wsniff`` can use a WHAD-compatible device to capture demodulated data on a
given frequency if all the required information is provided to correctly demodulate
a signal. The **PHY** domain needs to be specified, along with additional options:

.. code-block:: text

    wsniff [OPTIONS] phy [DOMAIN OPTIONS]


Specific PHY options
^^^^^^^^^^^^^^^^^^^^

* ``--frequency`` (``-f``): specifies the target frequency in Hz. This frequency
                            must be in the device' supported frequencies range.
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

Example of raw demodulation
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The following command will capture raw GFSK demodulated data from 2.402 GHz with a
datarate of 1 Mbsp and a deviation of 250 kHz:

.. code-block:: text

    $ wsniff --format=raw phy -f 2402000000 -gfsk -d 1000000 -dev 250000
    [ raw=False, timestamp=1294870503, rssi=-100, frequency=2402, iq=[] ]
    aa4010872314590606062040128680504c12c8a2ce0408b88211010117045210

    [ raw=False, timestamp=1294896651, rssi=-99, frequency=2402, iq=[] ]
    aa629409060eeb224300050821a2a9240329251603548055f891404301005b74

    [ raw=False, timestamp=1294904891, rssi=-99, frequency=2402, iq=[] ]
    aa370851bdec7a5a9a4e47ee5f57dc9761a1548e7a0ba846fade4d0ffd1ca06a

    [ raw=False, timestamp=1294926612, rssi=-98, frequency=2402, iq=[] ]
    aa20f401aa023f220c0409a7186ac1e028b012248482b17a552590b38a2024d2

    [ raw=False, timestamp=1294963494, rssi=-97, frequency=2402, iq=[] ]
    aa05c2718019014424f1973288a6447a0794b5055306a1b95081697ae462325e

    [ raw=False, timestamp=1295259594, rssi=-98, frequency=2402, iq=[] ]
    aa4c7eb4eb42e37d29c605802bf896f2716bfdad0889f39ebe4d310c17157988

    [ raw=False, timestamp=1295297166, rssi=-100, frequency=2402, iq=[] ]
    aa7510e3af36559684295bc64be201e0a2f56482afb52b80480d7a1456dcca12

    [ raw=False, timestamp=1295353577, rssi=-99, frequency=2402, iq=[] ]
    aa57b6dd7ee495b0bd77bc4c7ef3ddaaf6efa76626cf55c6223dfeeff79b4f3c

    [ raw=False, timestamp=1295450127, rssi=-98, frequency=2402, iq=[] ]
    aa97fd84fa59fa575a6fa09491ef61596f7672000fa4b4e09d90d3e2256123ef

    [ raw=False, timestamp=1295519023, rssi=-98, frequency=2402, iq=[] ]
    aa749fed7dc9e7bf1b7bdeeff7f6fffbbf75ff2de77f93afcffbff9ede92fff7

    [ raw=False, timestamp=1295530152, rssi=-100, frequency=2402, iq=[] ]
    aa129440282c9c800818095ad0020aac9212b840ae20c54b0c6d02058aa97362

Metadata is shown above each capture data, providing the received signal strength indicator (*RSSI*),
frequency in MHz. The ``raw`` flag correspond to the fact that this data has been
captured with a device that does not support raw packet sniffing, but it does not
matter in this case.

Metadata can be removed with ``--no-metadata``:

.. code-block:: text

    $ wsniff --format=raw phy --no-metadata -f 2402000000 -gfsk -d 1000000 -dev 250000
    aa0ed99b6be30c200dab53c04522001b038edc11395954a1a2d55a95a0c9e128
    aa0c18d611a22432ab51b510e1523b3c89054250919a6356500e236d5263084e
    aa502316bb10580b108801889240078231ae805334a2cc08a87654c041081504
    aab98181a44172e84707520148aa8d215c1c5e06f285512914164b8b22b6662f
    aa8531986ab966b22152053754583b6a0c28d4a6d97a50292b1504aa0d2d82d3
    aaed9a7d99c505545055bed56bf45c88e1c69cbd188aa6dc50ab32250b472e13
    aa2104ce05ab0d13037044b40c2765a7a30269254a392808023db6e491b82345
    aa3a06106c9294c8fc299c14348940a2dc15ac351510c1202951d4473a9c142d


Bluetooth Low Energy sniffing
-----------------------------

``wsniff`` provides specific features for sniffing Bluetooth Low Energy communications:

* sniffing a new connection from one device to another and capture all the packets exchanged
* sniffing advertisements on a specific channel
* discovering access addresses

Specific BLE options
^^^^^^^^^^^^^^^^^^^^

* ``--show-advertisements`` (``-a``): capture advertisements on current channel (default: 37)
* ``--follow-connection`` (``-f``): follow a new connection (CONN_REQ sniffing)
* ``--show-empty-packets`` (``-e``): show empty packets exchanged to keep the connection alive
* ``--access-addresses-discovery``: sniff on data channels (0-36) and identify potential access addresses
* ``--pairing`` (``-p``): sniff legacy pairing
* ``--access-address`` (``-aa``): set the access address corresponding to a connection to target
* ``--crc-init`` (``-crc``): set target connection CRC initial value
* ``--hop-interval`` (``-int``): set target connection hop interval
* ``--hop-increment`` (``-inc``): set target connection hop increment (CSA #1 only)
* ``--channel-map`` (``-chm``): set channel map for the target connection
* ``--channel`` (``-c``): select the channel to sniff
* ``--filter`` (``-f``): display only the packets matching the provided BD address
* ``--decrypt`` (``-d``): enable packet decryption
* ``--keys`` (``-k``): set decryption keys


Sniffing for advertisements
^^^^^^^^^^^^^^^^^^^^^^^^^^^

``wsniff`` provides the ``--show-advertisements / -a`` to capture BLE advertisements:

.. code-block:: text

    $ wsniff -i uart0 --format=hexdump ble -a
    [ timestamp=570898619, channel=37, rssi=-74, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, decrypted=False ]
    00000000: D6 BE 89 8E 02 22 28 53  77 03 D0 D0 1B FF 75 00  ....."(Sw.....u.
    00000010: 42 04 01 80 60 D0 D0 03  77 53 28 D2 D0 03 77 53  B...`...wS(...wS
    00000020: 27 01 00 00 00 00 00 00  05 DA 96                 '..........

    [ timestamp=570968147, channel=37, rssi=-62, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, decrypted=False ]
    00000000: D6 BE 89 8E 00 21 5C FC  60 38 C1 A4 02 01 05 03  .....!\.`8......
    00000010: 02 00 18 09 09 38 65 79  76 70 56 6D 71 09 FF 60  .....8eyvpVmq..`
    00000020: 01 54 10 5C FC 60 38 D0  1B 33                    .T.\.`8..3

The default channel used for sniffing is channel 37, but channel 38 or 39 can also be provided:

.. code-block:: text

    $ wsniff -i uart0 --format=hexdump ble -a -c 38
    [ timestamp=56547068, channel=38, rssi=-72, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, decrypted=False ]
    00000000: D6 BE 89 8E 02 22 28 53  77 03 D0 D0 1B FF 75 00  ....."(Sw.....u.
    00000010: 42 04 01 80 60 D0 D0 03  77 53 28 D2 D0 03 77 53  B...`...wS(...wS
    00000020: 27 01 00 00 00 00 00 00  05 DA 96                 '..........

    [ timestamp=56696161, channel=38, rssi=-59, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0, decrypted=False ]
    00000000: D6 BE 89 8E 00 21 5C FC  60 38 C1 A4 02 01 05 03  .....!\.`8......
    00000010: 02 00 18 09 09 38 65 79  76 70 56 6D 71 09 FF 60  .....8eyvpVmq..`
    00000020: 01 54 10 5C FC 60 38 D0  1B 33                    .T.\.`8..3


Sniffing new BLE connections
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``wsniff`` can also sniff the initiation of a new BLE connection using option ``--follow-connection / -f``
and save the exchanged data into a PCAP file (thanks to ``wsniff`` ``--output / -o`` option), as shown below:

.. code-block:: text

    $ wsniff -i uart0 -o ble-conn-capture.pcap --format=show ble --follow-connection

ESB sniffing
------------

Nordic Semiconductor's *Enhanced ShockBurst* protocol can also be sniffed with ``wsniff``. ``wsniff`` is able to:

* scan channels and capture ESB packets
* stay on a specific channel and capture all ESB packets
* follow a specific ESB device and capture every packet it sends

Specific ESB options
^^^^^^^^^^^^^^^^^^^^

* ``--channel`` (``-c``): select a channel (0-100) to sniff, by default ``wsniff`` will loop on all channels
* ``--address`` (``-f``): set a device address to follow
* ``--scanning`` (``-s``): scan channels and capture all ESB packets
* ``--acknowledgements`` (``-a``): enable ACK sniffing

Scanning channels and capturing ESB packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Using the ``--scanning / -s`` option, ``wsniff`` will loop on every channel and try
to capture as much packets as possible:

.. code-block:: text

    $ wsniff -i uart0 --format=hexdump esb --scanning
    [ raw=True, decrypted=False, timestamp=79542015, channel=4, rssi=-41, is_crc_valid=False, address=29:b9:81:2c:a4 ]
    00000000: AA 29 B9 81 2C A4 02 5C  6B 00                    .)..,..\k.

    [ raw=True, decrypted=False, timestamp=81547040, channel=5, rssi=-96, is_crc_valid=False, address=29:b9:81:2c:a4 ]
    00000000: AA 29 B9 81 2C A4 01 6C  08 00                    .)..,..l..

    [ raw=True, decrypted=False, timestamp=81554708, channel=5, rssi=-40, is_crc_valid=False, address=29:b9:81:2c:a4 ]
    00000000: AA 29 B9 81 2C A4 2A 00  61 00 00 7C 47 FF 80 00  .)..,.*.a..|G...
    00000010: 5C 35 DD 00                                       \5..

    [ raw=True, decrypted=False, timestamp=81562788, channel=6, rssi=-34, is_crc_valid=False, address=29:b9:81:2c:a4 ]
    00000000: AA 29 B9 81 2C A4 03 4C  4A 00                    .)..,..LJ.


Following a specific device
^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a specific device address is provided through the ``--address / -f`` option, ``wsniff`` will follow
this device and capture all the packets sent on a specific channel selected with the ``--scanning / -s`` option:

.. code-block:: text

    $ wsniff -i uart0 --format=hexdump esb --address 29:b9:81:2c:a4 --scanning
    [ raw=True, decrypted=False, timestamp=2780306, channel=5, rssi=-43, is_crc_valid=True, address=29:b9:81:2c:a4 ]
    00000000: AA 29 B9 81 2C A4 28 00  61 00 00 7F FF FF 80 00  .)..,.(.a.......
    00000010: 20 C8 86 00                                        ...

    [ raw=True, decrypted=False, timestamp=2788174, channel=5, rssi=-44, is_crc_valid=True, address=29:b9:81:2c:a4 ]
    00000000: AA 29 B9 81 2C A4 29 00  61 00 00 7F F7 FF 80 00  .)..,.).a.......
    00000010: 28 93 EA 00                                       (...

    [ raw=True, decrypted=False, timestamp=2796042, channel=5, rssi=-43, is_crc_valid=True, address=29:b9:81:2c:a4 ]
    00000000: AA 29 B9 81 2C A4 2A 00  61 00 00 7F 77 FF 80 00  .)..,.*.a...w...
    00000010: 29 51 F1 80

This mode will capture more packets as it does not rely on sniffing, it configures the WHAD device to capture
packets sent by the device identified by the specified address.


Logitech Unifying sniffing
--------------------------

Logitech Unifying protocol is based on Nordic's ESB protocol, thus this sniffer shares
some options with the ESB sniffer described above. However, ``wsniff`` provides a few
extra features when it comes to Logitech Unifying:

* pairing sniffing can be used to capture a keyboard pairing process and recover the shared encryption key
* decryption is supported and can be used to decrypt the payloads and sniff any keypress

Specific Logitech Unifying options
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* ``--channel`` (``-c``): select a channel (0-100) to sniff, by default ``wsniff`` will loop on all channels
* ``--address`` (``-f``): set a device address to follow
* ``--scanning`` (``-s``): scan channels and capture all ESB packets
* ``--acknowledgements`` (``-a``): enable ACK sniffing
* ``--pairing`` (``-p``): sniff pairing procedure and break key (if possible)
* ``--decrypt`` (``-d``): enable decryption
* ``--keys`` (``-k``): provide decryption key in the form of a 128-bit hex value

Capturing and decoding Logitech Unifying packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``wsniff`` when using the ``unifying`` domain will try to decode every *Logitech Unifying*
payload, if not encrypted:

.. code-block:: text

    $ wsniff -i uart0 --format=show unifying --scanning
    [ raw=True, decrypted=False, timestamp=519433337, channel=17, rssi=-40, is_crc_valid=False, address=29:b9:81:2c:a4 ]
    ###[ Enhanced ShockBurst packet ]### 
        preamble  = 0xaa
        address_length= 5
        address   = 29:b9:81:2c:a4
        payload_length= 10
        pid       = 2
        no_ack    = 0
        padding   = 0
        valid_crc = yes
        crc       = 0xc04b
    ###[ ESB Payload ]### 
    ###[ Logitech Unifying Payload ]### 
            dev_index = 0x0
            frame_type= 0xc2
            checksum  = 0x41
    ###[ Logitech Mouse Payload ]### 
            button_mask= 0x0
            unused    = 0
            movement  = '\\xff\\xff\\xff'
            wheel_y   = 0
            wheel_x   = 0

Decrypting encrypted Logitech Unifying packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An encryption key can be provided throught the ``--keys / -k`` option and decryption
enabled with option ``--decrypt / -d`` in order to decode any encrypted payload of
*Logitech Unifying* packets:

.. code-block:: text

    $ wsniff -i uart0 --format=show unifying --decrypt -k 086712d2f4f567662cb5ebafca20bb96

