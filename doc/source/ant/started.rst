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
------------------

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


Simulating ANT nodes
---------------------

ANT channels overview
^^^^^^^^^^^^^^^^^^^^^^

A typical ANT communication relies on an **ANT channel**, defined as a communication link established between a ANT Master 
(:class:`whad.ant.connector.master`) and a ANT Slave (:class:`whad.ant.connector.slave`).

A (logical) channel is defined by various parameters:

    - **device number**: 16-bit integer identifying the Master device itself
    - **device type**: 8-bit integer indicating the Master device type
    - **transmission type**: 8-bit integer indicating the type of transmission in use
    - **channel period**: duration in us before two consecutive transmissions by the Master device
    - **RF channel**: radio-frequency channel used by the communication, between 0 (2400MHz) and 99 (2499MHz)
    - **Network key**: network key associated with the logical channel
    - **unidirectional**: bolean indicating if the communication is unidirectional or bidirectional
    - **shared**: boolean indicating if the communication can be shared by multiple Slave devices
    - **background**: boolean indicating if the communication must be performed in background or foreground mode
    

Creating a new ANT Channel
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Simulating an ANT Master can be performed quite easily using  :class:`whad.ant.connector.master.Master` connector. 
Such a connector can be instantiated using the following code snippet:

.. code-block:: python

    from whad.ant import Master

    # [...]
    # Create a WHAD device
    dev = WhadDevice.create("uart0")
    # Instantiate a Master connector
    master = Master(dev)
    
    # [...]
    

Then, a channel can be created using `create_channel` method:

.. code-block:: python

    from whad.ant.crypto import ANT_PLUS_NETWORK_KEY

    # [...]
    channel = master.create_channel(
        device_number = 0x1234, 
        device_type = 12, 
        transmission_type = 1,
        channel_period = 8070,
        rf_channel = 50, 
        network_key = ANT_PLUS_NETWORK_KEY,
        unidirectional = False, 
        shared = False, 
        background = False
    )

If the channel has been successfully created, a :class:`whad.ant.stack.llm.AntChannel` object is returned, otherwise the `create_channel` returns None:

.. code-block:: python

    if channel is not None:
        while channel.is_opened():
            # [...]

The complete code snippet instantiating a Master connector and creating a channel is the following one:

.. code-block:: python

    from whad.ant import Master
    from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
    from whad.device import WhadDevice
    from whad.exceptions import WhadDeviceNotFound

    try:
        # Create a WHAD device
        dev = WhadDevice.create("uart0")
        # Instantiate a Master connector
        master = Master(dev)
        
        channel = master.create_channel(
            device_number = 0x1234, 
            device_type = 12, 
            transmission_type = 1,
            channel_period = 8070,
            rf_channel = 50, 
            network_key = ANT_PLUS_NETWORK_KEY,
            unidirectional = False, 
            shared = False, 
            background = False
        )

        if channel is not None:
            while channel.is_opened():
                # Interact with the channel here
                pass

        else:
            print('[e] An error occured during channel creation')
            exit(1)

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)


Searching for an ANT Channel
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Simulating an ANT slave is also quite easy: using a :class:`whad.ant.connector.slave.Slave` connector 
allows to easily search for a specific channel by calling the `search_channel` method:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ant import Slave

    # Create a WHAD device
    dev = WhadDevice.create("uart0")
    # Instantiate a Slave connector
    slave = Slave(dev)
    

    # Search for a bidirectional channel matching dev_num = 0x1234, dev_type = 12 & trans_type = 1
    channel = slave.search_channel(
        device_number = 0x1234, 
        device_type = 12, 
        transmission_type = 1,
        channel_period = 8070,
        rf_channel = 50, 
        network_key = ANT_PLUS_NETWORK_KEY,
        unidirectional = False, 
        shared = False, 
        background = False
    )

If a channel matching the provided filter is found, it will be opened and returned by the `search_channel` method 
as :class:`whad.ant.stack.llm.AntChannel` object, otherwise the `create_channel` returns *None*.

It is also possible to use the integer 0 for *device_number*, *device_type* and *transmission_type* parameters to act as a wildcard:

.. code-block:: python

    # Search for any bidirectional channel on RF channel 50
    channel = slave.search_channel(
        device_number = 0, # acts as wildcard
        device_type = 0, # acts as wildcard
        transmission_type = 0, # acts as wildcard

        channel_period = 8070,
        rf_channel = 50, 
        network_key = ANT_PLUS_NETWORK_KEY,
        unidirectional = False, 
        shared = False, 
        background = False
    )

The following code snippet instantiates a Slave connector and search for a channel with *dev_num = 0x1234*, *dev_type = 12* & *trans_type = 1*:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ant import Slave

    try:
        # Create a WHAD device
        dev = WhadDevice.create("uart0")
        # Instantiate a Slave connector
        slave = Slave(dev)
        

        # Search for a bidirectional channel matching dev_num = 0x1234, dev_type = 12 & trans_type = 1
        channel = slave.search_channel(
            device_number = 0x1234, 
            device_type = 12, 
            transmission_type = 1,
            channel_period = 8070,
            rf_channel = 50, 
            network_key = ANT_PLUS_NETWORK_KEY,
            unidirectional = False, 
            shared = False, 
            background = False
        )

        if channel is not None:
            while channel.is_opened():
                # Interact with the channel here
        else:
            print("[e] Channel not found.")
            exit(1)
    except WhadDeviceNotFound:
        print("[e] Whad Device not found.")
        exit(1)


Sending ANT messages in a channel
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

ANT traffic can be splitted into three main categories (called *data types* in ANT terminology):
    - **Broadcast**: Short message transmitted regularly, no acknowledgement 
    - **Acknowledged**: Short message transmitted once, expecting an acknowledgement 
    - **Burst**: Long message (splitted into several shorter ones) transmitted once, expecting an acknowledgement 

.. image:: ../../_static/ant/data-types.png
    :width: 400


Depending on the type of traffic you use, you will be able to transmit different kind of data.

Once you have opened a channel, interacting with the different kind of traffic is straightforward. 
You can use either `broadcast`, `ack` or `burst` methods directly over the channel object:

.. code-block:: python 

    if channel is not None:
        while channel.is_opened():

            # Send "Hello" in broadcast mode
            channel.broadcast(b"Hello")
            
            input()
            # Send "World" in acked mode
            success = channel.ack(b"World")
            if success:
                print("Acknowledgement received !")
            
            # Send a long message in burst mode
            success = channel.burst(b"WHAD is the best tool since scapy and this is a very nice documentation")
            if success:
                print("Acknowledgement received !")


Receiving traffic from a channel
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can override two callbacks on the `AntChannel` object if you want to customize the behaviour when a packet is received:
    - `on_broadcast` : callback called when a Broadcast is received
    - `on_ack_burst` : callback called when a Acked or Burst is received

Both receives the applicative payload as first argument when a corresponding frame is received.

For example, you can add a custom function to display received traffic:

.. code-block:: python

    def show_broadcast(packet):
        print("[i] Broadcast received: " + bytes(packet).hex())

    def show_ack_burst(packet):
        print("[i] Ack/Burst received: " + bytes(packet).hex())

    channel.on_broadcast = show_broadcast
    channel.on_ack_burst = show_ack_burst

    while channel.is_opened():
        # Interact with the channel here...
        pass

Using pre-defined profiles
^^^^^^^^^^^^^^^^^^^^^^^^^^^

ANT Profiles allow you to design a specific application over your ANT channel, and defines some default values for channel parameters.
It allows to both expose a custom and specialized API, and potentially match the expected parameters provided by a specification.

As an example, this code snippet uses the ANT+ Heart Rate Monitor profile to transmit random heart rate between 60 and 80bpm:

.. code-block:: python 
    
    from whad.ant import Master
    from whad.device import WhadDevice
    from whad.exceptions import WhadDeviceNotFound
    from whad.ant.stack.app.profiles.antplus.hrm import HeartRateMonitor

    import random
    import time

    try:
        # Create the WHAD Device
        dev = WhadDevice.create("uart0")
        
        # Instantiate a ANT+ HRM sensor profile
        profile = HeartRateMonitor()

        # Instantiate the connector with the selected profile
        master = Master(dev, profile=profile)

        # Create a compatible channel
        channel = master.create_channel()

        if channel is not None:
            print("Heart Rate Monitor Sensor started. Press Ctrl+C to stop.")
            # Use the specialized API from profile to transmit heart rate
            while channel.is_opened():
                profile.computed_heart_rate = random.randint(60,80)
                time.sleep(1)

    except KeyboardInterrupt:
        print("Sensor stopped, closing device...")
        dev.close()

    except WhadDeviceNotFound:
        print("WHAD Device not found !")
        exit(1)


In a very similar way, the corresponding ANT+ Heart Rate Display can be easily spawned using the following snippet:

.. code-block:: python 

    from whad.ant import Slave
    from whad.device import WhadDevice
    from whad.exceptions import WhadDeviceNotFound
    from whad.ant.stack.app.profiles.antplus.hrm import HeartRateDisplay

    import time



    try:
        # Create the WHAD Device
        dev = WhadDevice.create("uart1")

        # Get the ANT+ Heart Rate Display profile
        profile = HeartRateDisplay()

        # Create the slave ANT connector
        slave = Slave(dev, profile=profile)
        
        # Search for a compatible channel and start profile if found
        channel = slave.search_channel()
        if channel is not None:
            # Use the specialized API provided by the ANT+ HRM Display profile to iterate over received heart rates
            for heart_rate in profile.heart_rates():
                print(heart_rate)

    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] WHAD Device not found !')
        exit(1)


Customizing the behaviour of a pre-defined profile
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can easily customize the behaviour of a pre-defined profile by inheriting from the profile and 
overriding the methods you want to customize. For example, you can override `on_heart_rate_update` method 
on HRM display profile :class:`whad.ant.stack.app.profiles.antplus.HeartRateDisplay`:

.. code-block:: python

    class MyCustomDisplay(HeartRateDisplay):
        
        def on_heart_rate_update(self, heart_rate):
            print("[i] Heart rate has been updated: ", heart_rate, "bpm")


    # [...]
    
    # Create the WHAD Device
    dev = WhadDevice.create("uart1")

    # Get the customized ANT+ Heart Rate Display profile
    profile = MyCustomDisplay()

    # Create the slave ANT connector
    slave = Slave(dev, profile=profile)
    # [...]


Implementing a custom profile 
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is also possible to implement from scratch a custom ANT profile. 

First, implement a class inheriting from :class:`whad.ant.stack.app.profiles.AntProfile`:

.. code-block:: python

    class MyCustomProfile(AntProfile):
        pass

Then, defines as class attributes the main default parameters used to establish a compatible channel: 

.. code-block:: python

    class MyCustomProfile(AntProfile):

        DEVICE_NUMBER = 1234
        DEVICE_TYPE = 1
        TRANSMISSION_TYPE = 1
        CHANNEL_PERIOD = 8070
        SEARCH_TIMEOUT = 0
        DEFAULT_RF_CHANNEL = 50
        NETWORK_KEY = ANT_PLUS_NETWORK_KEY    


Finally, implement the behaviour of the profile when traffic is received, by 
overriding `on_broadcast` and `on_ack_burst` methods:

.. code-block:: python

    class MyCustomProfile(AntProfile):

        DEVICE_NUMBER = 1234
        DEVICE_TYPE = 1
        TRANSMISSION_TYPE = 1
        CHANNEL_PERIOD = 8070
        SEARCH_TIMEOUT = 0
        DEFAULT_RF_CHANNEL = 50
        NETWORK_KEY = ANT_PLUS_NETWORK_KEY    


        def on_broadcast(self, broadcast):
            print("Received broadcast: ")
            print(repr(broadcast))

        def on_ack_burst(self, ack_burst):
            print("Received ack / burst: ")
            print(repr(ack_burst))