"""
Pythonic LoRaWAN 1.0 stack
"""
from binascii import unhexlify
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
    """

    def __init__(self, connector, options={}):
        """
        Create an instance of LoRaWAN associated with a specific connector. This
        connector provides the transport layer.

        :param connector: Connector to use with this stack.
        :type connector: WhadDeviceConnector
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
        :return-type: bytes
        """
        return self.state.appkey
    
    def get_appeui(self):
        """Retrieve the current APP EUI
        """
        return self.state.appeui

    def is_device_allowed(self, dev_eui):
        """Check if a device is allowed to connect
        """
        return self.__connector.is_device_allowed(dev_eui)

    def on_frame(self, frame):
        """LoRaWAN frame callback.

        This callback handles received LoRaWAN frames.
        """
        # Forward frame to our link layer
        self.send('ll', frame)

        # Switch back to uplink
        self.__connector.uplink()

    @source('ll')
    def send_frame(self, frame, timestamp: float = None):
        """Send a LoRa frame to the current channel.
        """
        # Switch to RX1
        logger.debug('[phy] sending frame of %d bytes' % len(bytes(frame)))
        self.__connector.rx1()
        self.__connector.send(bytes(frame), timestamp=timestamp)
        
    def on_device_joined(self, dev_eui, dev_addr, appskey, nwkskey):
        """A device has just joined.
        """
        # Forward notification to connector.
        self.__connector.on_device_joined(dev_eui, dev_addr, appskey, nwkskey)

    def on_data_received(self, dev_eui, dev_addr, data:bytes, upcount):
        """Received data from device
        """
        return self.__connector.on_device_data(dev_eui, dev_addr, data, upcount)

LWGatewayStack.add(LWGwLinkLayer)