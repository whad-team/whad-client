from binascii import hexlify

from whad.device import WhadDevice
from whad.lorawan.stack import LWGatewayStack
from whad.scapy.layers.lorawan import PHYPayload
from whad.lorawan.channel import ChannelPlan
from whad.lorawan.connector import LoRaWAN
from whad.lorawan.app import LWApplication

import logging
logger = logging.getLogger(__name__)

class LWGateway(LoRaWAN):
    """LoRaWAN single-channel gateway implementation.

    This emulated single-channel LoRaWAN gateway handles a single
    application.
    """

    def __init__(self, device : WhadDevice = None, channel_plan : ChannelPlan = None, app:LWApplication=None, stack=LWGatewayStack):
        """Initialize a LoRaWAN gateway.

        :param device: WHAD compatible device to use for this gateway
        :type device: WhadDevice
        :param channel_plan: LoRaWAN channel plan to use
        :type channel_plan: ChannelPlan
        :param app: LoRaWAN application to bind to this gateway
        :type app: LWApplication
        :param stack: LoRaWAN gateway stack class to use
        :type stack: class
        """
        super().__init__(device=device, channel_plan=channel_plan)

        self.__app = app
        self.__stack = stack(
            self,
            options={
                'appkey': app.key,
                'appeui': app.eui,
                'll': {

                }
            }
        )

        # Inject devices (if any) into our LoRaWAN link-layer
        linklayer = self.__stack.get_layer('ll')
        for device in self.__app.nodes():
            print(device)
            linklayer.add_provisioned_device(
                device.dev_addr,
                device.dev_eui,
                device.appskey,
                device.nwkskey,
                device.upcount,
                device.dncount
            )

        # Start RF
        self.start()

    def on_packet(self, packet : bytes):
        """Process incoming packet

        :param packet: Incoming packet
        :type packet: bytes
        """
        # Add packet to our packet queue
        pkt = PHYPayload(bytes(packet))
        pkt.metadata = packet.metadata
        self.__stack.on_frame(pkt)

    def is_device_allowed(self, dev_eui : str) -> bool:
        """Check if device is allowed to connect to our application.

        :param dev_eui: Device EUI
        :type dev_eui: str

        :returns: True if device is allowed, False otherwise.
        :rtype: bool
        """
        # Forward to our application
        return self.__app.is_authorized(dev_eui)

    def on_device_joined(self, dev_eui : str, dev_addr : int, appskey : bytes, nwkskey : bytes):
        """Device joined callback

        This method processes an OTAA join event.

        :param dev_eui: Device EUI
        :type dev_eui: str
        :param dev_addr: Device network address
        :type dev_addr: int
        :param appskey: Device application session key
        :type appskey: bytes
        :param nwkskey: Device network encryption session key
        :type nwkske: bytes
        """
        logger.info('[gateway] Device %s joined network with address 0x%08x' % (
            dev_eui,
            dev_addr,
        ))

        self.__app.on_device_joined(
            dev_eui,
            dev_addr,
            appskey,
            nwkskey
        )
    
    def on_device_data(self, dev_eui : str, dev_addr : int, data : bytes, upcount : int) -> bytes:
        """Device incoming data callback

        :param dev_eui: Device EUI
        :type dev_eui: str
        :param dev_addr: Device network address
        :type dev_addr: int
        :param data: Data received by the device
        :type data: bytes
        :param upcount: uplink frame counter
        :type upcount: int

        :returns: Data to be sent back to the device
        :rtype: bytes
        """
        logger.info('[gateway] Device %s sent data: %s' % (
            dev_eui,
            hexlify(data)
        ))
        return self.__app.on_device_data(
            dev_eui,
            dev_addr,
            data,
            upcount
        )

    def stop(self):
        """Stop the Gateway and its associated application.
        """
        self.__app.stop()
        super().stop()