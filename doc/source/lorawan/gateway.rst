LoRaWAN Gateway emulation
=========================

WHAD provides a single-channel gateway emulation able to run a custom application
like a normal LoRaWAN application server would. The emulated gateway supports 
over-the-air activation (OTAA) as well as activation by personnalization (ABP).

This section explains how to create such a gateway and a custom application.

Create a LoRaWAN application
----------------------------

First, we need to create a custom LoRaWAN application to associate with our
emulated gateway. Any LoRaWAN application must inherit from :class:`whad.lorawan.app.LWApplication`,
as shown below:

.. code-block:: python

    from whad.lorawan.app import LWApplication

    class EchoApp(LWApplication):

        def __init__(self, devices):
            super().__init__(
                'c1:c2:c3:c4:c5:c6:c7:c8',          # APP EUI
                '00000000000000000000000000000000', # APP key
                devices=devices
            )

        def on_data(self, node: LWNode, data: bytes) -> bytes:
            # Return the same data (echo)
            return data

This is a simple application that will send back to a device any data sent to
the application through the gateway. This application has its own extended
unique ID (EUI) and 128-bit application key.

We then create an instance of our application that will be used by our
gateway:

.. code-block:: python

    # Create our app instance
    my_app = EchoApp(
        devices=[
            LWNode('74:a1:e4:c9:60:72:06:3a')
        ]
    )


When creating our application instance, we need to specify the devices' EUI in
order for the gateway to allow them to join its network. If no application
session key (`AppSKey`) or network session encryption key (`NwkSEncKey`) is provided, the device is
considered by the gateway as an allowed device that will join the network with
a join procedure (OTAA). If both keys are provided, then the device is considered
as a provisionned one and can start communicating with the application without
having to join the network.


Create a gateway to serve our application
-----------------------------------------

Once our application defined, we create an emulated gateway and tell this
gateway to use our application:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.lorawan.app import LWApplication, LWNode
    from whad.lorawan.connector.gateway import LWGateway

    # Create our single-channel channel plan
    class MyChannelPlan(ChannelPlan):
        """Single-channel EU868 compatible channel plan
        """
        def __init__(self):
            super().__init__(
                channels = [
                    Uplink(1, 868100000, 0),
                    Downlink(1, 868100000, 0)
                ],
                datarates = [
                    DataRate(sf=7, bw=125000),
                    DataRate(sf=7, bw=125000)
                ],

                rx2=Downlink(1, 868100000, 1)
            )

    class EchoApp(LWApplication):

        def __init__(self, devices):
            super().__init__(
                'c1:c2:c3:c4:c5:c6:c7:c8',          # APP EUI
                '00000000000000000000000000000000', # APP key
                devices=devices
            )

        def on_data(self, node: LWNode, data: bytes) -> bytes:
            # Return the same data (echo)
            return data

    # Create our app instance
    my_app = EchoApp(
        devices=[
            LWNode('74:a1:e4:c9:60:72:06:3a')
        ]
    )

    # Create our gateway
    device = WhadDevice.create('uart:/dev/ttyACM0)
    gw = LWGateway(
        device,
        MyChannelPlan,
        my_app
    )

    try:
        # wait
        input()
    except KeyboardInterrupt as kbd:
        gw.stop()

We create a custom channel plan for our single-channel gateway (see `<lorawan_channel_plan>`_
for more details about how to create a channel plan and its purpose) and
an instance of a LoRaWAN gateway using this channel plan, our application and
a compatible WHAD device connected to the host machine.

We then wait until a key is pressed, and serves the application through the
emulated gateway as long as it is running.

Persistence of LoRaWAN end nodes
--------------------------------

The LoRaWAN application class :class:`whad.lorawan.app.lWApplication` implements
a persistence of its data and especially information about its end nodes: EUI,
device address, encryption keys are saved in a JSON file named by default with
the application EUI, and stored in the working folder.

This file is automatically loaded at run time and saved when the application is
stopped.