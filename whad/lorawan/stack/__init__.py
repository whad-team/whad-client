"""
Pythonic LoRaWAN 1.0 stack
"""
from binascii import unhexlify
from whad.scapy.layers.lorawan import PHYPayload
from whad.lorawan.stack.llm import LWGwLinkLayer
from whad.lorawan.helpers import EUI
from whad.common.stack import LayerState, Layer, alias, source, state

import logging
logger = logging.getLogger(__name__)

class LWGatewayState(LayerState):
    """State associated with LoRaWAN Gateway stack.
    """

    def __init__(self):
        """Initialize default state.
        """
        super().__init__()

        # Set APPKey to default value
        self.appkey = unhexlify('00000000000000000000000000000000')
        self.appeui = EUI('01:02:03:04:05:06:07:08')


@alias('phy')
@state(LWGatewayState)
class LWGatewayStack(Layer):
    """LoRaWAN Gateway stack

    This stack implements the behavior of a LoRaWAN 1.0 gateway, allowing devices to join
    through OTAA or ABP.

    For now, MAC commands are not processed.
    """

    def __init__(self, connector, options={}):
        """
        Create an instance of LoRaWAN associated with a specific connector. This
        connector provides the transport layer.

        :param connector: Connector to use with this stack.
        :type connector: WhadDeviceConnector
        :param options: Stack layer options
        :type options: dict
        """

        super().__init__(options=options)

        # APPKey must be provided
        if 'appkey' in options:
            self.state.appkey = unhexlify(options['appkey'])

        # APP EUI too
        if 'appeui' in options:
            self.state.appeui = EUI(options['appeui'])

        # Save connector (used as PHY layer)
        self.__connector = connector

        # Configure hardware to listen on a random uplink channel
        self.__connector.uplink()

    def get_appkey(self):
        """Retrieve the current APPKey

        :returns: Current APPKey
        :rtype: bytes
        """
        return self.state.appkey
    
    def get_appeui(self):
        """Retrieve the current APP EUI

        :returns: Current EUI
        :rtype: str
        """
        return self.state.appeui

    def is_device_allowed(self, dev_eui : str) -> bool:
        """Check if a device is allowed to connect.

        :param dev_eui: Device EUI
        :type dev_eui: str
        :returns: True if device is allowed to join, False otherwise.
        :rtype: bool
        """
        return self.__connector.is_device_allowed(dev_eui)

    def on_frame(self, frame : PHYPayload):
        """LoRaWAN frame callback.

        This callback handles received LoRaWAN frames.

        :param frame: LoRaWAN frame
        :type frame: PHYPayload
        """
        # Forward frame to our link layer
        self.send('ll', frame)

        # Switch back to uplink
        self.__connector.uplink()

    @source('ll')
    def send_frame(self, frame : PHYPayload, timestamp : float = None):
        """Send a LoRa frame to the current channel.

        :param frame: LoRaWAN frame to send
        :type frame: PHYPayload
        :param timestamp: Timestamp at which the payload has to be sent (if not `None`)
        :type timestamp: float
        """
        # Switch to RX1
        logger.debug('[phy] sending frame of %d bytes' % len(bytes(frame)))
        self.__connector.rx1()
        self.__connector.send(bytes(frame), timestamp=timestamp)
        
    def on_device_joined(self, dev_eui : str, dev_addr : int, appskey : bytes, nwkskey : bytes):
        """A device has just joined.

        :param dev_eui: Device EUI
        :type dev_eui: str
        :param dev_addr: Device network address
        :type dev_addr: int
        :param appskey: Device application session key
        :type appskey: bytes
        :param nwkskey: Device network encrytion session key
        :type nwkskey: bytes
        """
        # Forward notification to connector.
        self.__connector.on_device_joined(dev_eui, dev_addr, appskey, nwkskey)

    def on_data_received(self, dev_eui : str, dev_addr : int, data : bytes, upcount : int) -> bytes:
        """Received data from device.

        :param dev_eui: Device EUI
        :type dev_eui: str
        :param dev_addr: Device network address
        :type dev_addr: int
        :param data: Data received
        :type data: bytes
        :param upcount: Uplink frame counter
        :type upcount: int
        :returns: Data to send back to the device
        :rtype: bytes
        """
        return self.__connector.on_device_data(dev_eui, dev_addr, data, upcount)

LWGatewayStack.add(LWGwLinkLayer)