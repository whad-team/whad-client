from binascii import hexlify
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

    DEFAULT_APP_KEY = '00000000000000000000000000000000'
    DEFAULT_APP_EUI = '01:02:03:04:05:06:07:08'

    def __init__(self, device=None, channel_plan : ChannelPlan = None, app:LWApplication=None, stack=LWGatewayStack):
        super().__init__(device=device, channel_plan=channel_plan)

        self.__app = app
        self.__stack = stack(
            self,
            options={
                'appkey': app.key,
                'appeui': app.eui,
            }
        )

        # Start RF
        self.start()

    def on_packet(self, packet):
        """
        """
        packet.show()
        # Add packet to our packet queue
        pkt = PHYPayload(bytes(packet))
        pkt.metadata = packet.metadata
        self.__stack.on_frame(pkt)

    def is_device_allowed(self, dev_eui):
        """Check if device is allowed to connect to our application.
        """
        # Forward to our application
        return self.__app.is_authorized(dev_eui)

    def on_device_joined(self, dev_eui, dev_addr, appskey:bytes, nwkskey:bytes):
        """Device joined callback
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
    
    def on_device_data(self, dev_eui, dev_addr, data, upcount):
        """Device sent data
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


