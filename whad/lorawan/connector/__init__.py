"""This module provides a connector to use LoRaWAN capable hardware.
"""
from time import sleep
from binascii import hexlify, unhexlify
from queue import Queue, Empty
from struct import pack, unpack
from Cryptodome.Cipher import AES
from Cryptodome.Hash import CMAC
from scapy.contrib.loraphy2wan import PHYPayload, Join_Request, Join_Accept

from whad.device import WhadDevice
from whad.phy.connector.lora import LoRa
from whad.lorawan.channel import EU868, ChannelModParams, ChannelPlan
from whad.lorawan.exceptions import NotStartedException

import logging
logger = logging.getLogger(__name__)

def eui_to_bytes(eui):
    values = eui.lower().split(':')[::-1]
    assert len(values) == 8
    return bytes([int(v, 16) for v in values])

def compute_mic(appkey, buffer):
    c = CMAC.new(appkey, ciphermod=AES)
    c.update(buffer)
    return c.digest()[:4]


class LoRaWAN(LoRa):
    '''Basic LoRaWAN connector to use with a LoRa compatible hardware.

    This connector provides the basic features to send and receive LoRaWAN packets
    with a specific channel plan.
    '''

    def __init__(self, device : WhadDevice = None, channel_plan : ChannelPlan = EU868):
        """Initialize this LoRaWAN connector.

        :param device: Compatible device to use.
        :type device: :class:`whad.device.WhadDevice`
        :param channel_plan: Channel plan to use
        :type channel_plan: :class:`whad.lorawan.channel.ChannelPlan`
        """
        super().__init__(device)

        # Configure channel plan
        logger.debug('Channel plan set to %s' % channel_plan.__name__)
        self.__channel_plan = channel_plan()
        self.__pkt_queue = Queue()
        self.__cr = 45

        # Keep track of current status
        self.__started = False

        # Default mode is uplink
        self.uplink()

    def reconfigure(self, channel: ChannelModParams, crc: bool = True, invert_iq : bool = False):
        '''Reconfigure hardware with provided parameters.

        :param channel: Target channel modulation parameters.
        :type channel: :class:`whad.lorawan.channel.ChannelModParams`
        :param crc: Enable CRC if set to `True`, disabled if set to `False`
        :type crc: bool, optional
        :param invert_iq: Invert IQ if set to `True`
        :type invert_iq: bool, optional
        '''
        logger.debug('Reconfiguring hardware for channel %s' % channel)

        # Reconfigure hardware (stop if necessary, then restart if we were already started)
        must_restart = self.__started
        if self.__started:
            logger.debug('Hardware was running, stopping ...')
            self.stop()
            logger.debug('Hardware stopped')

        # Set modulation parameters
        logger.debug('Reconfiguring core modulation parameters')
        self.sf = channel.spreading_factor
        self.bw = channel.bandwidth
        self.preamble_length = 8
        self.invert_iq = invert_iq
        logger.debug('Enabling CRC: %s' % crc)
        self.enable_crc(crc)
        self.enable_explicit_mode(True)
        logger.debug('Setting Freq: %d' % channel.frequency)
        self.set_frequency(channel.frequency)
        self.syncword = LoRa.SYNCWORD_LORAWAN

        # Restart hardware if required
        if must_restart:
            logger.debug('Resuming RX ...')
            self.start()

    def uplink(self):
        '''Configure hardware to transmit on a random uplink channel.

        A random uplink channel is picked from the ones defined in the channel
        plan, and hardware is reconfigured to listen and send on the corresponding
        frequency with the associated modulation parameters.
        '''
        self.__current_channel = self.__channel_plan.pick_channel()
        self.reconfigure(self.__current_channel)
        logger.debug('TX channel: %s' % self.__current_channel)

    def rx1(self):
        '''Configure hardware to listen on RX1.
        
        RX1 channel is chosen depending on the channel plan.
        '''
        # Retrieve RX1 channel modulation parameters from channel plan
        rx1_channel = self.__channel_plan.get_rx1(self.__current_channel.number)
        logger.debug('RX1 channel: %s' % rx1_channel)

        # Change hardware configuration only if needed
        if rx1_channel != self.__current_channel or self.crc_enabled:
            self.reconfigure(rx1_channel, crc=False, invert_iq=True)

    def rx2(self):
        '''Configure hardware to listen on RX2.

        RX2 channel is usually a single channel with more reliable modulation
        parameters used as a backup channel for downlink communication.
        '''
        rx2_channel = self.__channel_plan.get_rx2()
        logger.debug('RX2 channel: %s' % rx2_channel)

        # Change hardware configuration only if needed
        if rx2_channel != self.__current_channel or self.crc_enabled:
            self.reconfigure(rx2_channel, crc=False, invert_iq=True)


    def start(self, coding_rate: int=45):
        """Start the LoRaWAN adapter into receive mode by default.
        """
        # Start listening
        logger.debug('Starting hardware (RX mode)')
        super().start()
        self.__started = True


    def stop(self):
        """Stop the LoRaWAN adapter.
        """
        logger.debug('Stopping hardware')
        super().stop()
        self.__started = False


    def send(self, packet, timestamp: float = None):
        '''Send a LoRaWAN frame with current LoRa modulation parameters.

        :param packet: Packet to send
        :type packet: :class:`whad.scapy.layers.lorawan.PHYPayload`
        :param timestamp: If provided, will send the packet at the given timestamp
        :type timestamp: float, optional
        '''
        # Make sure hardware has been started
        if not self.__started:
            raise NotStartedException

        # Send LoRaWAN frame
        if timestamp is not None:
            logger.debug('Programming packet %s at %f' % (hexlify(bytes(packet)), timestamp))
            pkt_id = super().schedule_send(packet, timestamp)
            logger.debug('packet id is %d' % pkt_id)
            return pkt_id
        else:
            logger.debug('Sending packet %s' % hexlify(bytes(packet)))
            super().send(packet)


    def on_packet(self, packet : PHYPayload):
        """Callback method for incoming packet processing

        :param packet: Received packet
        :type packet: :class:`whad.scapy.layers.lorawan.PHYPayload`
        """
        logger.debug('Received LoRaWAN payload: %s' % hexlify(bytes(packet)))

        # Add packet to our packet queue
        pkt = PHYPayload(bytes(packet))
        pkt.metadata = packet.metadata
        self.__pkt_queue.put(pkt)


    def wait_packet(self, timeout : float = None):
        """Wait for a LoRaWAN packet.

        If timeout is set, wait for the given time and return None if no
        packet has been received. If timeout is not provided, this method
        will block until a valid packet is received.

        :param timeout: Timeout in seconds
        :type timeout: float, optional
        """
        try:
            logger.debug('Waiting for incoming packet ...')
            packet = self.__pkt_queue.get(block=True, timeout=timeout)           
            logger.debug('Packet received !')
            return packet
        except Empty as empty:
            return None

    def __process_join_accept(self, app_key, packet):
        '''Process an encrypted JoinAccept
        '''
        # Decrypt and verify JoinAccept
        if len(packet.Join_Accept_Encrypted) > 0:
            ja_enc = packet.Join_Accept_Encrypted
            
            # Decrypt JoinAccept
            c = AES.new(app_key, mode=AES.MODE_ECB)
            ja_dec = c.encrypt(ja_enc)
            ja_dec, mic = ja_dec[:-4], ja_dec[-4:]
            resp = Join_Accept(ja_dec)

            logger.debug('Decrypted JoinAccept: %s' % hexlify(ja_dec))
            logger.debug('JoinAccept MIC: %s' % hexlify(mic))
                            
            # Check MIC
            buf = b'\x20' + ja_dec
            exp_mic = compute_mic(app_key, buf)
            if exp_mic == mic:
                logger.debug('MIC is OK')
                # Return JoinAccept if MIC is OK
                return resp
            else:
                logger.debug('MIC does not match (expected: %s)' % exp_mic)
                return None

    def join(self, app_key : bytes, app_eui : str, dev_eui : str, dev_nonce : int):
        '''Perform an OTAA join procedure

        See section 6.2.1 from LoRaWAN Specifications version 1.1

        :param app_key: Application key
        :type app_key: bytes
        :param app_eui: Application EUI
        :type app_eui: str
        :param dev_eui: Device EUI
        :type dev_eui: str
        :param dev_nonce: Device nonce
        :type dev_nonce: str
        '''
        logger.debug('Building a join request for APPEUI %s, DEVEUI %s' % (
            app_eui,
            dev_eui
        ))
        logger.debug('Using DevNonce=0x%04x' % dev_nonce)

        join_req = Join_Request()
        join_req.AppEUI = eui_to_bytes(app_eui)
        join_req.DevEUI = eui_to_bytes(dev_eui)
        join_req.DevNonce = dev_nonce

        logging.debug('Generating PHY payload from JoinRequest ...')
        phy_jr = PHYPayload()
        phy_jr.MType = 0x00 # join request
        phy_jr.Join_Request_Field = join_req
        mic = compute_mic(app_key, bytes(phy_jr)[:-4])
        phy_jr.MIC = unpack('>I', mic)[0]
        logging.debug('PHY[JoinRequest]: %s' % hexlify(bytes(phy_jr)))
        logging.debug(' - MIC: %s' % hexlify(mic))
        
        # Send join request
        self.send(bytes(phy_jr))

        # Wait for join request to be sent
        sleep(.3)

        # Switch to RX1
        logger.debug('Opening RX1 window...')
        self.rx1()

        # Wait for a join accept
        ja = self.wait_packet(5.5)
        if ja is not None:
            # Decrypt and verify JoinAccept
            result = self.__process_join_accept(app_key, ja)
            if result is not None:
                logger.debug('Received a JoinAccept on RX1')
                return result
                    
        # Switch to RX2
        logger.debug('Opening RX2 window...')
        self.rx2()

        # Wait for a JoinAccept (again)
        ja = self.wait_packet(5.5)
        if ja is not None:
            # Decrypt and verify JoinAccept
            result = self.__process_join_accept(ja)
            if result is not None:
                logger.debug('Received a JoinAccept on RX2')
                return result
            
        # Join failed
        logger.debug('No JoinAccept received, join procedure FAILED')

        # Switch back to uplink
        self.uplink()

        return None
        