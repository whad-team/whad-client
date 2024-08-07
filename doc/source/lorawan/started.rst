Getting started
===============

WHAD provides dedicated tools to interact with LoRaWAN networks and compatible
devices. These tools are based on PHY's LoRa capabilities.

LoRaWAN Channel Plan
--------------------

Depending on where you are on the globe, LoRaWAN gateways are using different
configurations with a given number of uplink channels with associated frequencies,
as well as a given number of downlink channels.

This is why WHAD's LoRaWAN implementation requires the user to specify a channel
plan, an object that specifies the channels, frequencies and data rates to use
for uplink and downlink communication.

.. _lorawan_channel_plan:

Defining a custom channel plan
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A channel plan can be easily defined as follows:

.. code-block:: python

    from whad.lorawan.channel import ChannelPlan, Uplink, Downlink, DataRate

    class MyChannelPlan(ChannelPlan):
        """Custom channel plan
        """

        def __init__(self):
            super().__init__(
                channels = [
                    # Uplink (1-8, DR5)
                    Uplink(1, 868100000, 5),
                    Uplink(2, 868300000, 5),
                    Uplink(3, 868500000, 5),
                    Uplink(4, 867100000, 5),
                    Uplink(5, 867300000, 5),
                    Uplink(6, 867500000, 5),
                    Uplink(7, 867700000, 5),
                    Uplink(8, 867900000, 5),
                    Downlink(1, 868100000, 5),
                    Downlink(2, 868300000, 5),
                    Downlink(3, 868500000, 5),
                    Downlink(4, 867100000, 5),
                    Downlink(5, 867300000, 5),
                    Downlink(6, 867500000, 5),
                    Downlink(7, 867700000, 5),
                    Downlink(8, 867900000, 5),
                ],

                datarates = [
                    DataRate(12, 125000),
                    DataRate(11, 125000),
                    DataRate(10, 125000),
                    DataRate(9, 125000),
                    DataRate(8, 125000),
                    DataRate(7, 125000),
                ],

                # Downlink RX2, DR0
                rx2=Downlink(10, 869525000, 0)
            )

Basically, the `channels` parameter is used to declare a set of RF channels,
used for uplink and downlink, while the `datarates` parameter defines the
supported data rates. An additionnal `rx2` parameter allows to set the default
second RX window configuration.

Uplink and downlink channels are defined with the following parameters:

* The first parameter specifies the channel index ;
* the second parameter its frequency ;
* and the last one the data rate to use as an index into the `datarates` array.

Data rates are defined with the following parameters:

* The first parameter specifies the *spreading factor* to use, from 7 to 12 ;
* the second and last parameter specifies the bandwidth to use and must be 125000, 250000 or 500000.

The channel plan will then be used by the :py:class:`whad.lorawan.connector.LoRaWAN`
connector to use the correct channels for sending and receiving data.


Default channel plans
~~~~~~~~~~~~~~~~~~~~~

WHAD implements some default channel plans for some regions:

* :py:class:`whad.lorawan.channel.EU868` for Europe (default SF7 with 125kHz bandwidth)


Configuring a LoRaWAN end device
--------------------------------

Use the :py:class:`whad.lorawan.connector.LoRaWAN` connector to create a LoRaWAN
end device using a custom channel plan:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.lorawan.connector import LoRaWAN
    from whad.lorawan.channel import ChannelPlan, Uplink, Downlink, DataRate

    # Create our freq plan
    class MyChannelPlan(ChannelPlan):
        def __init__(self):
            super().__init__(
                channels = [
                    Uplink(1, 868100000, 0),
                    Downlink(1, 868100000, 0)
                ],
                datarates = [
                    DataRate(sf=7, bw=125000),
                    DataRate(sf=12, bw=125000)
                ],

                rx2=Downlink(1, 868100000, 1)
            )    

    lwan = LoRaWAN(WhadDevice.create('uart0'), channel_plan=MyChannelPlan)


Receiving LoRaWAN packets
-------------------------

When a LoRaWAN connector instance is configured, it can be used to receive any
LoRaWAN packet. By default, the hardware is put in receive mode with the provided
channel plan.

.. code-block:: python

    from whad.device import WhadDevice
    from whad.lorawan.connector import LoRaWAN
    from whad.lorawan.channel import ChannelPlan, Uplink, Downlink, DataRate

    # Create our freq plan
    class MyChannelPlan(ChannelPlan):
        def __init__(self):
            super().__init__(
                channels = [
                    Uplink(1, 868100000, 0),
                    Downlink(1, 868100000, 0)
                ],
                datarates = [
                    DataRate(sf=7, bw=125000),
                    DataRate(sf=12, bw=125000)
                ],

                rx2=Downlink(1, 868100000, 1)
            )    
    # Create our LoRaWAN connector
    lwan = LoRaWAN(WhadDevice.create('uart0'), channel_plan=MyChannelPlan)

    # Start receiving by default
    lwan.start()

    # Listen for any valid packet received
    while True:
        packet = lwan.wait_packet()
        packet.show()

Received packets have a timestamp that specifies when the packet has been received
by the hardware. It can be later used to schedule a packet to be sent after a
specific delay. This feature is used in our gateway implementation to send back
some packets after a very precise delay as specified in the LoRaWAN specification.


Sending LoRaWAN packets
-----------------------

LoRaWAN packets can be sent through this connector and it is also possible to
specify when a packet must be sent with the use of the `timestamp` parameter.

The :py:meth:`whad.lorawan.connector.LoRaWAN.send` method is used to send a
packet:

.. code-block:: python

    lwan.send(packet)

And it is possible to tell the WHAD hardware to schedule a packet for a given
timestamp:

.. code-block:: python

    lwan.send(packet, timestamp=1500.123456)

