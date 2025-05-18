Getting started
===============

*Enhanced ShockBurst* is a wireless communication protocol designed by Nordic
Semiconductor and supported by a set of wireless system-on-chips including
the *nRF24* and *nRF5x* series. See `Nordic Semiconductor ESB documentation <https://infocenter.nordicsemi.com/index.jsp?topic=%2Fcom.nordic.infocenter.sdk5.v12.0.0%2Fesb_users_guide.html>`_ for
more details.

Scan available devices
----------------------

Use the :class:`whad.esb.connector.scanner.Scanner` class to instantiate
a BLE device scanner and detect all the available devices.

.. code-block:: python

    from whad import UartDevice
    from whad.esb import Scanner

    scanner = Scanner(UartDevice('/dev/ttyUSB0'))
    scanner.start()
    for device in scanner.discover_devices():
        print(device)


Sniffing for Enhanced ShockBurst frames
---------------------------------------

Use the :class:`whad.esb.connector.sniffer.Sniffer` to sniff for frames:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.esb import Sniffer

    # Create a sniffer tied to an existing compatible interface
    sniffer = Sniffer(WhadDevice.create('uart:/dev/ttyUSB0'))
    
    # Sniff on channel 5
    sniffer.channel = 5

    # Start sniffing
    sniffer.start()

    # Capture frames and display them
    for frame in sniffer.sniff():
        frame.show()


The :func:`whad.esb.Sniffer.sniff` method yield *Scapy* packets
that can be processed like any other *Scapy* packets.

In the example above, our sniffer captured frames on a specific channel but it also
can loop on every available channels and capture frames by setting its `channel` property
to `None`, as shown below:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.esb import Sniffer

    # Create a sniffer tied to an existing compatible interface (nRF52840)
    sniffer = Sniffer(WhadDevice.create('uart:/dev/ttyUSB0'))
    
    # Loop on all available channels
    sniffer.channel = None

    # Start sniffing
    sniffer.start()

    # Capture frames and display them
    for frame in sniffer.sniff():
        frame.show()


Receiving Enhanced ShockBurst frames sent by a device
-----------------------------------------------------

It is also possible to configure a compatible WHAD device to receive frames sent to
a specific device address by setting it in *receiver mode* (also known as *PRX mode*).
In the following example, we configure our compatible WHAD device (nRF52840) to receive
and display *Enhanced ShockBurst* frames sent to address *11:22:33:44:55* on channel 5:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.esb import PRX

    # Create a receiver tied to a compatible interface (nRF52840)
    receiver = PRX(WhadDevice.create('uart:/dev/ttyUSB0'))

    # Wait for packets on channel 5
    receiver.address = '11:22:33:44:55'
    receiver.channel = 5

    # Show received frames
    for frame in receiver.stream():
        frame.show()

In *PRX* mode, our compatible WHAD device behaves as a normal *Enhanced Shockburst*
receiver and will send *acks* if required by the transmitter. A small ESB stack is implemented
and used by our :class:`whad.esb.PRX` connector to send these *acks*.

.. warning::

    If a WHAD device is set in *PRX* mode while another compatible receiver is also active,
    there is a risk that both of them will send *acks* that overlap and avoid correct reception
    by the transmitter expecting an *ack*.


Sending Enhanced ShockBurst frames to a device
----------------------------------------------

Similarly, a compatible WHAD device can send frames to a target *Enhanced ShockBurst* device
when set in *transmitter mode* (or *PTX* mode):

.. code-block:: python

    from whad.device import WhadDevice
    from whad.esb import PTX

    # Create a receiver tied to a compatible interface (nRF52840)
    transmitter = PTX(WhadDevice.create('uart:/dev/ttyUSB0'))

    # Configure transmitter to send to device with address 11:22:33:44:55 on
    # channel 5
    transmitter.address = '11:22:33:44:55'
    transmitter.channel = 5

    # Send data
    transmitter.send_data(b"This is a payload")

When the device's channel is unknown, there is a procedure defined in Nordic Semiconductor's
*Enhanced ShockBurst* protocol that allows a transmitter to discover a target device's channel.
This pocedure is known as a *ping procedure*, and consists in basically sending *ping frames*
on all channels and listening to detect an answer. This procedure is available in *PTX* and
can be used as follows:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.esb import PTX

    # Create a receiver tied to a compatible interface (nRF52840)
    transmitter = PTX(WhadDevice.create('uart:/dev/ttyUSB0'))

    # Configure transmitter to send to device with address 11:22:33:44:55
    transmitter.address = '11:22:33:44:55'

    # Synchronize with device (find device channel)
    if transmitter.synchronize()
        # Send data once synchronized
        transmitter.send_data(b"This is a payload")
    else:
        print("Cannot synchronize with target device")

