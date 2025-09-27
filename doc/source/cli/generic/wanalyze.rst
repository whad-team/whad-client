wanalyze: generic traffic analysis tool
========================================

``wanalyze`` allows to analyze traffic from packets captured from sniffing or through
PCAP replay. It is based on several traffic analyzers, allowing to infer various information
from a stream of packets (e.g., decryption keys, profiles, audio stream, keystrokes...).
It is intended to be used chained with other WHAD tools.

Usage
-----

.. code-block:: text

    ... | wanalyze [OPTIONS] [ANALYZER]

By default, ``wanalyze`` will use all available traffic analyzers for the traffic linked to the used domain.
If provided, only the traffic analyzers provided as a series of expression ANALYZER will be applied.
For example, the following command will use all available BLE analyzers:

.. code-block:: text

  $ wplay --flush ble_pairing.pcap | wanalyze

The following command will use only *"legacy_pairing_cracking"* and *"encrypted_session_initialization"*:

.. code-block:: text

  $ wplay --flush ble_pairing.pcap | wanalyze legacy_pairing_cracking encrypted_session_initialization

It is also possible to select only a specific field of an analyzer output, using the expression ANALYZER.FIELD.
For example, the following command line will display only the Short-Term Key (STK) of the *"legacy_pairing_cracking"* analyzer:

.. code-block:: text

  $ wplay --flush ble_pairing.pcap | wanalyze legacy_pairing_cracking.stk


Command-line options
^^^^^^^^^^^^^^^^^^^^

**wextract** supports the following options:

* ``--trigger``: display when an analyzer has been triggered
* ``--json``: serialize output into JSON format
* ``--packets`` (``-p``): display packets associated with the analyzer
* ``--label``: display labels before output value
* ``--delimiter`` (``-d`` / ``-D``): provide a delimiter inserted between outputs
* ``--raw`` (``-r``): dump output directly to stdout buffer (e.g., to process raw bytes)
* ``--list`` (``-l``): display a list of available analyzers
* ``--set`` (``-s``): set a configuration parameter that will be used by the selected analyzers 

.. include:: debug-options.rst

Displaying the available analyzers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To display the list of available analyzers by domain, just use the ``--list`` (or ``-l``) option:

.. code-block:: text

    $ wanalyze -l
    Available analyzers:  ble
    - peripheral_information : adv_data, bd_addr, addr_type
    - encrypted_session_initialization : master_skd, master_iv, slave_skd, slave_iv, started
    - legacy_pairing_cracking : tk, stk
    - ltk_distribution : ltk, rand, ediv
    - irk_distribution : address, irk
    - csrk_distribution : csrk
    - profile_discovery : profile

    Available analyzers:  rf4ce
    - key_cracking : key
    - audio : raw_audio
    - keystroke : key

    Available analyzers:  unifying
    - pairing_cracking : key
    - mouse : x, y, wheel_x, wheel_y, button
    - keystroke : key
        parameter locale (default: "fr")

    Available analyzers:  zigbee
    - touchlink_key_cracking : key_index, encrypted_key, decrypted_key
    - transport_key_cracking : transport_key

Setting configuration parameters
--------------------------------

Analyzers can expose one or more configuration options to allow users to change the way
they process traffic. The Unifying `keystroke` analyzer for instance exposes a `locale`
configuration parameter that can be set to specify a locale different from the one
defined for the current terminal.

To set a specific configuration option, use ``--set OPTION=VALUE``, or its short form ``-s OPTION=VALUE``.  

Breaking encryption keys
-------------------------

It's quite common for wireless protocols to use weak pairing procedures, that can be attacked to recover the encryption keys.
WHAD provides various traffic analyzers allowing to perform such offline attacks, targeting various protocols.

Breaking Bluetooth Low Energy legacy pairing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The first version of Bluetooth Low Energy pairing is flawed and is known to be vulnerable to CrackLE attack.
``wanalyze`` allows to easily retrieve encryption key if the pairing procedure has been captured and if legacy pairing was in use.

To perform this attack, you can use the *"legacy_pairing_cracking"* analyzer.
To demonstrate the attack, let's first download a PCAP file containing a vulnerable pairing:

.. code-block:: text

    wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/ble_pairing.pcap

We can easily replay this PCAP file using ``wplay`` tool, with option ``--flush`` to display all the traffic without taking into account the timestamps:

.. code-block:: text

    $ wplay --flush ble_pairing.pcap
    [ raw=True, decrypted=False, timestamp=0, channel=37, rssi=-44, direction=0, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x8e89bed6 crc=0xec6ba9 |<BTLE_ADV  RxAdd=public TxAdd=random ChSel=0 RFU=0 PDU_type=CONNECT_REQ Length=0x22 |<BTLE_CONNECT_REQ  InitA=63:5b:46:e8:b3:81 AdvA=74:da:ea:91:47:e3 AA=0xf5a6dd92 crc_init=0x852f0a win_size=0x2 win_offset=0x1 interval=0x24 latency=0x0 timeout=0x1f4 chM=0x1fffffffff SCA=0 hop=6 |>>>

    [ raw=True, decrypted=False, timestamp=341, channel=6, rssi=0, direction=1, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x92dda6f5 crc=0x5509b6 |<BTLE_DATA  RFU=0 MD=0 SN=0 NESN=0 LLID=control len=9 |<BTLE_CTRL  opcode=LL_FEATURE_REQ |<LL_FEATURE_REQ  feature_set=le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext+ll_privacy+ext_scan_filter+le_2m_phy+rx_mod_idx+le_coded_phy+le_ext_adv+le_periodic_adv+ch_sel_alg |>>>>

    [ raw=True, decrypted=False, timestamp=4841, channel=12, rssi=0, direction=1, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x92dda6f5 crc=0x5509b6 |<BTLE_DATA  RFU=0 MD=0 SN=0 NESN=0 LLID=control len=9 |<BTLE_CTRL  opcode=LL_FEATURE_REQ |<LL_FEATURE_REQ  feature_set=le_encryption+conn_par_req_proc+ext_reject_ind+slave_init_feat_exch+le_ping+le_data_len_ext+ll_privacy+ext_scan_filter+le_2m_phy+rx_mod_idx+le_coded_phy+le_ext_adv+le_periodic_adv+ch_sel_alg |>>>>

    [ raw=True, decrypted=False, timestamp=4871, channel=12, rssi=0, direction=2, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x92dda6f5 crc=0xba762b |<BTLE_DATA  RFU=0 MD=0 SN=0 NESN=1 LLID=continue len=0 |>>

    [ raw=True, decrypted=False, timestamp=9341, channel=18, rssi=0, direction=1, connection_handle=0, is_crc_valid=True, relative_timestamp=0 ]
    <BTLE  access_addr=0x92dda6f5 crc=0x1c7b2b |<BTLE_DATA  RFU=0 MD=0 SN=1 NESN=1 LLID=continue len=0 |>>

    [...]

Let's analyze this traffic with our *"legacy_pairing_cracking"* analyzer:

.. code-block:: text

    $ wplay --flush ble_pairing.pcap | wanalyze legacy_pairing_cracking                                                                                                                    ST 27   main 
    [✓] legacy_pairing_cracking → completed
      - tk:  00000000000000000000000000000000
      - stk:  f72fa81ee5e86708243e920107de31b9

The output indicates both the temporary key ("tk") and the Short-Term Key (stk).

The Short-Term Key is then used to encrypt the key distribution between the communicating devices.
Let's decrypt the traffic with ``wplay`` by using option ``-d`` (decrypt) and by providing the STK with option ``-k`` (keys):

.. code-block:: text

    $ wplay --flush ble_pairing.pcap -d -k f72fa81ee5e86708243e920107de31b9


Then, we can easily extract the various distributed keys using wanalyze on the decrypted stream:

.. code-block:: text

    $ wplay --flush ble_pairing.pcap -d -k f72fa81ee5e86708243e920107de31b9 | wanalyze
    [...]
    [✓] ltk_distribution → completed
      - ltk:  2867a99de17e3548cc17cf16ef96050e
      - rand:  38a7dcd10a1a93c6
      - ediv:  29507

    [✓] irk_distribution → completed
      - address:  74:da:ea:91:47:e3
      - irk:  13c3a68f113b764cc8e73f55fc52c002

    [✓] csrk_distribution → completed
      - csrk:  c3062f93c91eef96354edcd70a1a0306

    [✓] ltk_distribution → completed
      - ltk:  8ec147a3b442e2ea77b3e98705f26ca8
      - rand:  51064044944874a2
      - ediv:  55664

    [✓] irk_distribution → completed
      - address:  64:a2:f9:be:de:f1
      - irk:  b3370bec1cef2ecec83a035478eba33a

    [✓] csrk_distribution → completed
      - csrk:  9581eb690fbb3b8dfeb97b7293917bd4

Extracting keys from ZigBee join procedure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When a new device wants to join an existing ZigBee network, the Network Key will be transmitted over the air, encrypted with a pre-shared Transport Key.
Some Transport Key are publicly known, and can be used to decrypt the packet including the Network Key.

For example, Philips Hue uses the following Transport Key for their ZigBee networks: *81:42:86:86:5D:C1:C8:B2:C8:CB:C5:2E:5D:65:D1:B8*.

Let's download a PCAP file containing such procedure:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/zigbee_philips_hue_association.pcap


We can then replay and decrypt the traffic using ``wplay`` with ``-d`` (decrypt) option. We need to provide the transport key using ``-k`` (keys) option.

.. code-block:: text

    $ wplay --flush zigbee_philips_hue_association.pcap -d -k 81:42:86:86:5D:C1:C8:B2:C8:CB:C5:2E:5D:65:D1:B8

To extract the network key, we only need to use ``wanalyze`` and observe the output of the analyzer *"transport_key_cracking"*:

.. code-block:: text

    $ wplay --flush zigbee_philips_hue_association.pcap -d -k 81:42:86:86:5D:C1:C8:B2:C8:CB:C5:2E:5D:65:D1:B8 | wanalyze
    [✓] transport_key_cracking → completed
      - transport_key:  02398409245156e31d98a92157a8a66f


Breaking ZigBee touchlink protocol
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Touchlink commissioning protocol has been introduced in ZigBee 3.0, and allows to facilitate key provisioning in ZigBee network.
While the Touchlink protocol is supposed to use encrypted traffic to transport the Network Key, it relies on an AES key which has been leaked on twitter, allowing to retrieve the key exchanged using this method.
You can easily break Touchlink protocol using ``wanalyze`` tool. Let's first download a PCAP file containing Touchlink provisioning:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/zigbee_touchlink_provisioning.pcap

To break the key, let's replay the PCAP file using ``wplay`` with ``--flush`` option to ignore timestamps and combine it with ``wanalyze``:

.. code-block:: text

    $ wplay --flush zigbee_touchlink_provisioning.pcap | wanalyze                                                                                                                   SIGINT  ST 27   main 
    [✓] touchlink_key_cracking → completed
      - key_index:  4
      - encrypted_key:  7b9f58e4c50ef979437ecf5ba7c63853
      - decrypted_key:  0134fe9e66908714e694f1d28403eed6


You can then use the decrypted key to decrypt traffic by providing the key using ``-k`` option:

.. code-block:: text

    $ wplay --flush zigbee_touchlink_provisioning.pcap -d -k 0134fe9e66908714e694f1d28403eed6
    [...]

    [ decrypted=True, timestamp=3102611, channel=11, rssi=-45, is_fcs_valid=True, lqi=188 ]
    <Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=False fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=227 fcs=0xc803 |<Dot15d4Data  dest_panid=0xc802 dest_addr=0xffff src_addr=0xf |<ZigbeeNWK  discover_route=1 proto_version=2 frametype=data flags=security destination=0xfffd source=0xf radius=12 seqnum=98 |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x1018 source=00:0b:57:ff:fe:11:1a:2c key_seqnum=0 data=<ZigbeeAppDataPayload  frame_control= delivery_mode=group_addressing aps_frametype=data group_addr=0x512 cluster=0x6 profile=HA_Home_Automation src_endpoint=1 counter=243 |<ZigbeeClusterLibrary  reserved=0 disable_default_response=0 command_direction=0 manufacturer_specific=0 zcl_frametype=profile-wide transaction_sequence=3 command_identifier=read_attributes |<ZCLGeneralReadAttributes  attribute_identifiers=[0x0] |>>> |>>>>

    [ decrypted=False, timestamp=3129623, channel=11, rssi=-45, is_fcs_valid=True, lqi=188 ]
    <Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=True fcf_pending=False fcf_security=False fcf_frametype=Command fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=254 fcs=0x26b8 |<Dot15d4Cmd  dest_panid=0xc802 dest_addr=0xf src_addr=0x1 cmd_id=DataReq |>>

    [ decrypted=False, timestamp=3129677, channel=11, rssi=-46, is_fcs_valid=True, lqi=192 ]
    <Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=False fcf_ackreq=False fcf_pending=False fcf_security=False fcf_frametype=Ack fcf_srcaddrmode=None fcf_framever=0 fcf_destaddrmode=None fcf_reserved_2=0 seqnum=254 fcs=0xab49 |>

    [ decrypted=True, timestamp=3167748, channel=11, rssi=-45, is_fcs_valid=True, lqi=200 ]
    <Dot15d4FCS  fcf_reserved_1=0 fcf_panidcompress=True fcf_ackreq=False fcf_pending=False fcf_security=False fcf_frametype=Data fcf_srcaddrmode=Short fcf_framever=0 fcf_destaddrmode=Short fcf_reserved_2=0 seqnum=228 fcs=0xb19 |<Dot15d4Data  dest_panid=0xc802 dest_addr=0xffff src_addr=0xf |<ZigbeeNWK  discover_route=0 proto_version=2 frametype=command flags=security+extended_src destination=0xfffc source=0xf radius=1 seqnum=102 ext_src=00:0b:57:ff:fe:11:1a:2c |<ZigbeeSecurityHeader  reserved1= extended_nonce=1 key_type=network_key nwk_seclevel=None fc=0x1019 source=00:0b:57:ff:fe:11:1a:2c key_seqnum=0 data=<ZigbeeNWKCommandPayload  cmd_identifier=link status res5=0 last_frame=1 first_frame=1 entry_count=0 |> |>>>>


Breaking RF4CE pairing procedure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

RF4CE protocol uses a weak pairing procedure, that can be exploited to recover the encryption key by analyzing pairing traffic.

Let's download a PCAP file containing such weak pairing procedure:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/rf4ce_pairing_keystrokes_audio.pcap

Then, cracking the key is as simple as running the following command:

.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap | wanalyze
    [✓] key_cracking → completed
      - key:  48ca7e9fdbc168b0297dd97d4f7f85a8

We can then easily reuse this key with ``wplay`` to decrypt all the encrypted traffic:

.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8


Breaking Logitech Unifying pairing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Wireless keyboards and mices from Logitech commonly relies on Logitech Unifying protocol (or one of its variants).
This protocol also uses a vulnerable pairing procedure, which can be attacked easily if the pairing packets have been captured.

You can use ``wsniff`` and ``-p`` option (pairing) to synchronize with the channel hopping algorithm and sniff a Logitech Unifying pairing:

.. code-block:: text

    $ wsniff -i uart0 unifying -p

Alternatively, you can download a PCAP file containing a captured pairing using the following command:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/logitech_pairing.pcap

And replay it using ``wplay``:

.. code-block:: text

    $ wplay --flush logitech_pairing.pcap


Recovering the key is then as simple as running ``wanalyze`` on the corresponding stream to perform the attack:

.. code-block:: text

    $ wplay --flush logitech_pairing.pcap | wanalyze
    [✓] pairing_cracking → completed
      - key:  02bea8b5ef61037e87882e4daebf403b

Then, let's use this key to decrypt some encrypted traffic. Download the PCAP file containing the encrypted traffic:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/logitech_encrypted_traffic.pcap

You can then use ``wplay`` with ``-d`` option (decrypt) and provide the key using ``-k`` (keys):

.. code-block:: text

    $ wplay --flush logitech_encrypted_traffic.pcap -d -k 02bea8b5ef61037e87882e4daebf403b
    [...]
    [ raw=True, decrypted=True, timestamp=50231, channel=0, is_crc_valid=True, address=a8:41:9e:b5:0f ]
    <ESB_Hdr  preamble=0xaa address_length=5 address=a8:41:9e:b5:0f payload_length=22 pid=2 no_ack=0 padding=0 valid_crc=yes crc=0xe235 |<Logitech_Unifying_Hdr  dev_index=0x0 frame_type=0xd3 checksum=0x81 |<Logitech_Encrypted_Keystroke_Payload  hid_data='\x00\x0b' unknown=201 aes_counter=3087930536 unused='' |>>>
    [...]
    [ raw=True, decrypted=True, timestamp=56916, channel=0, is_crc_valid=True, address=a8:41:9e:b5:0f ]
    <ESB_Hdr  preamble=0xaa address_length=5 address=a8:41:9e:b5:0f payload_length=22 pid=2 no_ack=0 padding=0 valid_crc=yes crc=0xd893 |<Logitech_Unifying_Hdr  dev_index=0x0 frame_type=0xd3 checksum=0xb1 |<Logitech_Encrypted_Keystroke_Payload  hid_data='' unknown=201 aes_counter=3087930537 unused='' |>>>
    [...]


Extract complex data from packet streams
-----------------------------------------

Various complex data can be extracted from packet stream, using various available analyzers.

Extracting Bluetooth Low Energy GATT profile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If a discovery procedure has been captured, it's possible to use *"profile_discovery"* to recover the GATT profile.

For example, the following PCAP contain such a discovery procedure:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/ble_pairing.pcap

You can extract the discovered profile using:

.. code-block:: text

    $ wplay --flush ble_pairing.pcap | wanalyze profile_discovery
    [✓] profile_discovery → completed
      - profile:  Service 1800 (handles from 1 to 11):
      Characteristic 2A00 (handle:2, value handle: 3, props: R)
      Characteristic 2A01 (handle:4, value handle: 5, props: R)
      Characteristic 2A02 (handle:6, value handle: 7, props: R)
      Characteristic 2A03 (handle:8, value handle: 9, props: W)
      Characteristic 2A04 (handle:10, value handle: 11, props: R)
    Service 1801 (handles from 12 to 15):
      Characteristic 2A05 (handle:13, value handle: 14, props: I)
        Descriptor 2902 (handle: 15)
    Service 180A (handles from 16 to 30):
      Characteristic 2A23 (handle:17, value handle: 18, props: R)
      Characteristic 2A24 (handle:19, value handle: 20, props: R)
      Characteristic 2A25 (handle:21, value handle: 22, props: R)
      Characteristic 2A26 (handle:23, value handle: 24, props: R)
      Characteristic 2A27 (handle:25, value handle: 26, props: R)
      Characteristic 2A28 (handle:27, value handle: 28, props: R)
      Characteristic 2A29 (handle:29, value handle: 30, props: R)
    Service a8b3fff0-4834-4051-89d0-3de95cddd318 (handles from 31 to 47):
      Characteristic a8b3fff1-4834-4051-89d0-3de95cddd318 (handle:32, value handle: 33, props: RW)
        Descriptor 2901 (handle: 34)
      Characteristic a8b3fff2-4834-4051-89d0-3de95cddd318 (handle:35, value handle: 36, props: R)
        Descriptor 2901 (handle: 37)
      Characteristic a8b3fff3-4834-4051-89d0-3de95cddd318 (handle:38, value handle: 39, props: W)
        Descriptor 2901 (handle: 40)
      Characteristic a8b3fff4-4834-4051-89d0-3de95cddd318 (handle:41, value handle: 42, props: N)
        Descriptor 2902 (handle: 43)
        Descriptor 2901 (handle: 44)
      Characteristic a8b3fff5-4834-4051-89d0-3de95cddd318 (handle:45, value handle: 46, props: R)
        Descriptor 2901 (handle: 47)
    Service a8b3ffe0-4834-4051-89d0-3de95cddd318 (handles from 48 to 57):
      Characteristic a8b3ffe1-4834-4051-89d0-3de95cddd318 (handle:49, value handle: 50, props: R)
        Descriptor 2901 (handle: 51)
      Characteristic a8b3ffe2-4834-4051-89d0-3de95cddd318 (handle:52, value handle: 53, props: RW)
        Descriptor 2901 (handle: 54)
      Characteristic a8b3ffe3-4834-4051-89d0-3de95cddd318 (handle:55, value handle: 56, props: W)
        Descriptor 2901 (handle: 57)
    Service f000ffc0-0451-4000-b000-000000000000 (handles from 58 to 65535):
      Characteristic f000ffc1-0451-4000-b000-000000000000 (handle:59, value handle: 60, props: WN)
        Descriptor 2902 (handle: 61)
        Descriptor 2901 (handle: 62)
      Characteristic f000ffc2-0451-4000-b000-000000000000 (handle:63, value handle: 64, props: WN)
        Descriptor 2902 (handle: 65)
        Descriptor 2901 (handle: 66)


If you want to use the profile in another tool, for example ``wble-periph``, you can easily format the output using the ``--json`` option:

.. code-block:: text

    $ wplay --flush ble_pairing.pcap | wanalyze profile_discovery.profile --json
    {"services": [{"uuid": "1800", "type_uuid": "2800", "start_handle": 1, "end_handle": 11, "characteristics": [{"handle": 2, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 3, "uuid": "2A00"}, "descriptors": []}, {"handle": 4, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 5, "uuid": "2A01"}, "descriptors": []}, {"handle": 6, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 7, "uuid": "2A02"}, "descriptors": []}, {"handle": 8, "uuid": "2803", "properties": 8, "security": 0, "value": {"handle": 9, "uuid": "2A03"}, "descriptors": []}, {"handle": 10, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 11, "uuid": "2A04"}, "descriptors": []}]}, {"uuid": "1801", "type_uuid": "2800", "start_handle": 12, "end_handle": 15, "characteristics": [{"handle": 13, "uuid": "2803", "properties": 32, "security": 0, "value": {"handle": 14, "uuid": "2A05"}, "descriptors": [{"handle": 15, "uuid": "2902"}]}]}, {"uuid": "180A", "type_uuid": "2800", "start_handle": 16, "end_handle": 30, "characteristics": [{"handle": 17, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 18, "uuid": "2A23"}, "descriptors": []}, {"handle": 19, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 20, "uuid": "2A24"}, "descriptors": []}, {"handle": 21, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 22, "uuid": "2A25"}, "descriptors": []}, {"handle": 23, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 24, "uuid": "2A26"}, "descriptors": []}, {"handle": 25, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 26, "uuid": "2A27"}, "descriptors": []}, {"handle": 27, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 28, "uuid": "2A28"}, "descriptors": []}, {"handle": 29, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 30, "uuid": "2A29"}, "descriptors": []}]}, {"uuid": "a8b3fff0-4834-4051-89d0-3de95cddd318", "type_uuid": "2800", "start_handle": 31, "end_handle": 47, "characteristics": [{"handle": 32, "uuid": "2803", "properties": 10, "security": 0, "value": {"handle": 33, "uuid": "a8b3fff1-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 34, "uuid": "2901"}]}, {"handle": 35, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 36, "uuid": "a8b3fff2-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 37, "uuid": "2901"}]}, {"handle": 38, "uuid": "2803", "properties": 8, "security": 0, "value": {"handle": 39, "uuid": "a8b3fff3-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 40, "uuid": "2901"}]}, {"handle": 41, "uuid": "2803", "properties": 16, "security": 0, "value": {"handle": 42, "uuid": "a8b3fff4-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 43, "uuid": "2902"}, {"handle": 44, "uuid": "2901"}]}, {"handle": 45, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 46, "uuid": "a8b3fff5-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 47, "uuid": "2901"}]}]}, {"uuid": "a8b3ffe0-4834-4051-89d0-3de95cddd318", "type_uuid": "2800", "start_handle": 48, "end_handle": 57, "characteristics": [{"handle": 49, "uuid": "2803", "properties": 2, "security": 0, "value": {"handle": 50, "uuid": "a8b3ffe1-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 51, "uuid": "2901"}]}, {"handle": 52, "uuid": "2803", "properties": 10, "security": 0, "value": {"handle": 53, "uuid": "a8b3ffe2-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 54, "uuid": "2901"}]}, {"handle": 55, "uuid": "2803", "properties": 8, "security": 0, "value": {"handle": 56, "uuid": "a8b3ffe3-4834-4051-89d0-3de95cddd318"}, "descriptors": [{"handle": 57, "uuid": "2901"}]}]}, {"uuid": "f000ffc0-0451-4000-b000-000000000000", "type_uuid": "2800", "start_handle": 58, "end_handle": 65535, "characteristics": [{"handle": 59, "uuid": "2803", "properties": 28, "security": 0, "value": {"handle": 60, "uuid": "f000ffc1-0451-4000-b000-000000000000"}, "descriptors": [{"handle": 61, "uuid": "2902"}, {"handle": 62, "uuid": "2901"}]}, {"handle": 63, "uuid": "2803", "properties": 28, "security": 0, "value": {"handle": 64, "uuid": "f000ffc2-0451-4000-b000-000000000000"}, "descriptors": [{"handle": 65, "uuid": "2902"}, {"handle": 66, "uuid": "2901"}]}]}]}


It can easily be redirected to a file using a basic bash redirection:

.. code-block:: text

    $ wplay --flush ble_pairing.pcap | wanalyze profile_discovery.profile --json > profile.json

Extracting RF4CE keystrokes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

RF4CE is commonly used by Remote Controllers (RC), and it's possible to implement a basic keylogger to retrieve pressed buttons.

For example, the following PCAP file contains such keystrokes:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/rf4ce_pairing_keystrokes_audio.pcap

Let's decrypt the traffic using the corresponding encryption key:


.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8


Then, the *"keystroke"* analyzer can be used to infer the keystrokes:


.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8 | wanalyze keystroke
    [✓] keystroke → completed
      - key:  7

    [✓] keystroke → completed
      - key:  0

    [✓] keystroke → completed
      - key:  6

    [✓] keystroke → completed
      - key:  1

    [✓] keystroke → completed
      - key:  2

    [✓] keystroke → completed
      - key:  3

    [✓] keystroke → completed
      - key:  4

    [✓] keystroke → completed
      - key:  5

    [✓] keystroke → completed
      - key:  6


You can display the keystroke without the analyzers information by selecting the key field:

.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8 | wanalyze keystroke.key
    7
    0
    6
    1
    2
    3
    4
    5
    6

Extracting RF4CE audio stream
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Some RF4CE Remote Controllers (RC) support audio commands. Such audio streams can be extracted using *"audio"* analyzers.

The following PCAP file contains such audio stream:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/rf4ce_pairing_keystrokes_audio.pcap

Let's decrypt the traffic using the corresponding encryption key:

.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8

Finally, we can extract the audio stream by using the *"audio"* analyzer:

.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8 | wanalyze audio
    [✓] audio → completed
      - raw_audio:  52494646e402010057415645666d74201000000001000100803e0000007d00000200100064617461c002010000 [...]

The displayed bytes corresponds to a WAV file. It can be easily dumped by :

  * selecting "raw_audio" field (``wanalyze audio.raw_audio``)
  * dumping raw bytes to stdout buffer (``--raw`` / ``-r``)

Let's play it:

.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8 | wanalyze audio.raw_audio --raw | play -

Or export it to a WAV file:

.. code-block:: text

    $ wplay --flush rf4ce_pairing_keystrokes_audio.pcap -d -k 48ca7e9fdbc168b0297dd97d4f7f85a8 | wanalyze audio.raw_audio --raw > stream.wav

Extracting Logitech Unifying mouse movements and clicks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

``wanalyze`` can be used to extract mouse actions (movements & clicks) from Logitech Unifying mouse traffic.

For example, let's download a PCAP file corresponding to a capture of a Logitech mouse:

.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/logitech_mouse.pcap

If you use ``wanalyze`` on the corresponding packet stream, the *"mouse"* analyzer will be automatically triggered:

.. code-block:: text

    $ wplay --flush logitech_mouse.pcap | wanalyze
    [✓] mouse → completed
      - x:  0
      - y:  -1
      - wheel_x:  0
      - wheel_y:  0
      - button:

    [✓] mouse → completed
      - x:  0
      - y:  -2
      - wheel_x:  0
      - wheel_y:  0
      - button:

    [✓] mouse → completed
      - x:  1
      - y:  -3
      - wheel_x:  0
      - wheel_y:  0
      - button:

    [✓] mouse → completed
      - x:  0
      - y:  -2
      - wheel_x:  0
      - wheel_y:  0
      - button:
    [...]


Let's format the output to be used with ``wuni-mouse`` tool:

.. code-block:: text

    $ wplay --flush logitech_mouse.pcap | wanalyze mouse.x mouse.y mouse.wheel_x mouse.wheel_y mouse.button -d ","
    0,-1,0,0,
    0,-2,0,0,
    1,-3,0,0,
    0,-2,0,0,
    0,-2,0,0,
    1,-2,0,0,
    0,-2,0,0,
    1,-2,0,0,
    0,-2,0,0,
    1,-2,0,0,
    0,-2,0,0,
    0,-2,0,0,
    1,-2,0,0,
    0,-2,0,0,
    0,-2,0,0,
    1,-2,0,0,
    0,-1,0,0,
    0,-2,0,0,
    0,-2,0,0,
    [...]


Redirect it to a file:

.. code-block:: text

    $ wplay --flush logitech_mouse.pcap | wanalyze mouse.x mouse.y mouse.wheel_x mouse.wheel_y mouse.button -d "," > capture.mouse

You can then easily use it with ``wuni-mouse`` tool to replay mouse traffic over the air:

.. code-block:: text

    $ cat capture.mouse | wuni-mouse -i uart0 -a ca:e9:06:ec:a4
    Mouse found and locked, sending moves received on stdin...


Extracting Logitech Unifying keyboard keystrokes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It's also quite easy to implement a wireless keylogger targeting Logitech Unifying keyboard using ``wanalyze``.

As an example, let's download some traffic from a Logitech Unifying keyboard:


.. code-block:: text

    $ wget https://github.com/whad-team/whad-client/raw/main/whad/resources/pcaps/logitech_encrypted_traffic.pcap

You can then use ``wplay`` with ``-d`` option (decrypt) and provide the key using ``-k`` (keys):

.. code-block:: text

    $ wplay --flush logitech_encrypted_traffic.pcap -d -k 02bea8b5ef61037e87882e4daebf403b
    [...]
    [ raw=True, decrypted=True, timestamp=50231, channel=0, is_crc_valid=True, address=a8:41:9e:b5:0f ]
    <ESB_Hdr  preamble=0xaa address_length=5 address=a8:41:9e:b5:0f payload_length=22 pid=2 no_ack=0 padding=0 valid_crc=yes crc=0xe235 |<Logitech_Unifying_Hdr  dev_index=0x0 frame_type=0xd3 checksum=0x81 |<Logitech_Encrypted_Keystroke_Payload  hid_data='\x00\x0b' unknown=201 aes_counter=3087930536 unused='' |>>>
    [...]
    [ raw=True, decrypted=True, timestamp=56916, channel=0, is_crc_valid=True, address=a8:41:9e:b5:0f ]
    <ESB_Hdr  preamble=0xaa address_length=5 address=a8:41:9e:b5:0f payload_length=22 pid=2 no_ack=0 padding=0 valid_crc=yes crc=0xd893 |<Logitech_Unifying_Hdr  dev_index=0x0 frame_type=0xd3 checksum=0xb1 |<Logitech_Encrypted_Keystroke_Payload  hid_data='' unknown=201 aes_counter=3087930537 unused='' |>>>
    [...]

Extracting the keystrokes is as simple as combining ``wplay`` with ``wanalyze``:

.. code-block:: text

    $ wplay --flush logitech_encrypted_traffic.pcap -d -k 02bea8b5ef61037e87882e4daebf403b | wanalyze
    [✓] keystroke → completed
      - key:  a

    [✓] keystroke → completed
      - key:  b

    [✓] keystroke → completed
      - key:  c

    [✓] keystroke → completed
      - key:  d

    [✓] keystroke → completed
      - key:  e
    [...]

Output can be formatted easily, by selecting the key field of the *"keystroke"* analyzer:

.. code-block:: text

    $ wplay --flush logitech_encrypted_traffic.pcap -d -k 02bea8b5ef61037e87882e4daebf403b | wanalyze keystroke.key
    a
    b
    c
    d
    e
    f
    g
    h

By default, the selected locale is the one configured for the current terminal but it is possible to
select a different one by setting the `locale` configuration parameter:

.. code-block:: text

    $ wplay --flush logitech_encrypted_traffic.pcap -d -k 02bea8b5ef61037e87882e4daebf403b | wanalyze --set locale=us keystroke.key
    q
    b
    c
    d
    e
    f
    g
    h

Similarly to mouse traffic, you can extract this output in a file:

.. code-block:: text

    $ wplay --flush logitech_encrypted_traffic.pcap -d -k 02bea8b5ef61037e87882e4daebf403b | wanalyze keystroke.key > capture.keyboard

And replay it using ``wuni-keyboard`` as unencrypted traffic:

.. code-block:: text

    $ cat capture.keyboard | wuni-keyboard -i uart0 -a ca:e9:06:ec:a4 -l fr
    a
    b
    c
    d
    e
    f
    g
    h

Or as encrypted traffic by providing the key:

.. code-block:: text

    $ cat capture.keyboard | wuni-keyboard -i uart0 -a ca:e9:06:ec:a4 -l fr -k 02bea8b5ef61037e87882e4daebf403b
    a
    b
    c
    d
    e
    f
    g
    h
