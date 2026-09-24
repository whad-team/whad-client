Getting started
===============

*ANT* is a proprietary wireless communication protocol designed by Dynastream Innovations (bought by Garmin) and supported by a set of wireless system-on-chips including
the *nRF24* and *nRF5x* series. 

It is mainly used by sport and health oriented sensors & displays, such as Heart Rate Monitor (HRM) or Bicycle Candence & Speed sensors.

While the ANT protocol defines the lowest part of the protocol stack, two additional applicative layers can be instantiated on top of ANT:
    - *ANT+*, a set of profiles standardizing the communication between low energy sensors
    - *ANT-FS*, a file sharing protocol built over ANT

See `This is ANT website <https://thisisant.com>`_ for more details.

Scan available devices
----------------------

Use the :class:`whad.ant.connector.scanner.Scanner` class to instantiate
a ANT device scanner and detect all the available devices.

.. code-block:: python

    from whad import UartDevice
    from whad.ant import Scanner

    scanner = Scanner(WhadDevice.create('uart0'))
    scanner.start()

    for device in scanner.discover_devices():
        print(device)


The :meth:`whad.ant.connector.scanner.Scanner.discover_devices` method can be filtered to select specific ANT packet fields:
    - *device_type* 
    - *device_number*
    - *transmission_type* 

For example, the following code snippet discover only devices matching the condition `transmission_type = 1` & `device_type = 120` (e.g. ANT+ HRM).

.. code-block:: python

    for device in scanner.discover_devices(device_type=120, transmission_type=1):
        print(device)


A *timeout* value can also be provided to automatically terminates the scan after a specific duration (in seconds):

.. code-block:: python

    # Terminates after three seconds
    for device in scanner.discover_devices(timeout = 3):
        print(device)


Finally, it's also possible to take potential updates into account (re-yielding the device) by altering the *updates* indicator:


.. code-block:: python

    # Yield the device again if its state has been updated
    for device in scanner.discover_devices(updates = True):
        print(device)



A discovered device is implemented as a :class:`whad.ant.scanning.ANTDiscoveredDevice` object. It can be manipulated easily using its property:


.. code-block:: python
    
    for device in scanner.discover_devices():
        print("The following device has been discovered:")
        print("  - Device number: ", device.device_number)
        print("  - Device type: ", device.device_type)
        print("  - Transmission type: ", device.transmission_type)
        print("  - RSSI: ", device.rssi)
        print("  - List of RF channels: ", device.channels)
        print("  - Last RF channel: ", device.last_channel)
        print("  - Last observed payload: ", device.last_payload)
        print("  - Last observed timestamp: ", device.last_timestamp)
        print()

Sniff ANT traffic
----------------------

The :class:`whad.ant.connector.sniffer.Sniffer` class implements a sniffer
detecting ANT frames. This sniffer can be used to sniff ANT frames, including 
ANT+ & ANT-FS traffic.

Sniffing ANT+ traffic
^^^^^^^^^^^^^^^^^^^^^^
The following snippet allows basic ANT+ sniffing:

.. code-block:: python

    from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
    from whad.device import WhadDevice
    from whad.ant import Sniffer

    # Instantiate a compatible device
    device = WhadDevice.create('uart0')

    # Wraps device with a ANT sniffer
    sniffer = Sniffer(device)

    # Configure the sniffer
    sniffer.network_key =  ANT_PLUS_NETWORK_KEY
    sniffer.channel = 57

    sniffer.device_number = 0 # 0 acts as a wildcard for filtering
    sniffer.device_type = 0 # 0 acts as a wildcard for filtering
    sniffer.transmission_type = 0 # 0 acts as a wildcard for filtering


    # Sniff packets for 30 seconds
    for packet in sniffer.sniff(timeout=30.0):
        packet.show()

Any ANT+ frame will be shown whatever the device is.

It is also possible to filter out results, based on the device number, the device type or 
the transmission type. As an example, the following configuration allows to focus only on 
Heart Rate Monitor (`device_type = 120`) with `transmission_type` set to `1`:

.. code-block:: python

    from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
    from whad.device import WhadDevice
    from whad.ant import Sniffer

    # Instantiate a compatible device
    device = WhadDevice.create('uart0')

    # Wraps device with a ANT sniffer
    sniffer = Sniffer(device)

    # Configure the sniffer
    sniffer.network_key =  ANT_PLUS_NETWORK_KEY
    sniffer.channel = 57

    sniffer.device_number = 0 # 0 acts as a wildcard for filtering
    sniffer.device_type = 120
    sniffer.transmission_type = 1

    # Sniff packets for 30 seconds
    for packet in sniffer.sniff(timeout=30.0):
        packet.show()


Packets can be easily processed by an asynchronous callback using `attach_callback` instead of `sniff`:

.. code-block:: python

    def on_received_packet(pkt):
        pkt.show()

    # [...]
    sniffer.attach_callback(on_received_packet)

Sniffing ANT-FS traffic
^^^^^^^^^^^^^^^^^^^^^^^^

It is also possible to easily monitor ANT-FS traffic by setting the correct network key and configure the RF channel:

.. code-block:: python

    from whad.ant.crypto import ANT_FS_NETWORK_KEY
    from whad.device import WhadDevice
    from whad.ant import Sniffer

    # Instantiate a compatible device
    device = WhadDevice.create('uart0')

    # Wraps device with a ANT sniffer
    sniffer = Sniffer(device)

    # Configure the sniffer
    sniffer.network_key =  ANT_FS_NETWORK_KEY
    sniffer.channel = 62

    sniffer.device_number = 0 # 0 acts as a wildcard for filtering
    sniffer.device_type = 0
    sniffer.transmission_type = 0

    # Sniff packets for 30 seconds
    for packet in sniffer.sniff(timeout=30.0):
        packet.show()


Let's note that the sniffer can automatically switch to another RF channel if an `ANT-FS Link Packet` is detected, according to 
the received `rf_channel` field. Such option can be enabled by configuring the `follow` property:

.. code-block:: python

    # Enable channel follow mechanism
    sniffer.follow = True

    # Disable channel follow mechanism
    sniffer.follow = False


Using a custom ANT Network Key
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

ANT relies on a specific 8 bytes-long value called **Network key**.
A limited set of values are considered as valids, according to a basic checking algorithm. 
The validity algorithm is implemented in WHAD as an helper function in the ::class:`whad.ant.crypto` module, and can 
be used to check a key:

.. code-block:: python

    from whad.ant.crypto import is_valid_network_key

    candidate_network_key = bytes.fromhex("45C372BDFB21A5B9")
    if is_valid_network_key(candidate_network_key):
        sniffer.network_key = candidate_network_key
        # [...]


This value is mainly used to generate a 2 bytes long synchronization word, specific to the network key in use. 
Radio GFSK receiver is then configured to match this value in the demodulated bitstream and detect corresponding ANT frames.

The synchronization word can be generated from a given network key using `generate_sync_from_network_key` helper function:

.. code-block:: python

    from whad.ant.crypto import generate_sync_from_network_key

    candidate_network_key = bytes.fromhex("45C372BDFB21A5B9")
    sync_word = generate_sync_from_network_key(candidate_network_key)



Finally, sniffer can also be configured to use a valid network key by providing as a 8 bytes value the network key:

.. code-block:: python

    sniffer.network_key = bytes.fromhex("45C372BDFB21A5B9")
