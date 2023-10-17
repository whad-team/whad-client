from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceDisconnected
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter,is_message_type
from whad import WhadDomain, WhadCapability
from whad.protocol.generic_pb2 import ResultCode
from whad.device.virtual.qemu.constants import QEMUNrfDomains
from whad.protocol.esb.esb_pb2 import \
    Sniff as EsbSniff, \
    Send as EsbSend, \
    Start as EsbStart, \
    Stop as EsbStop, \
    SetNodeAddress as EsbSetNodeAddress, \
    PrimaryReceiverMode as EsbPrimaryReceiverMode, \
    PrimaryTransmitterMode as EsbPrimaryTransmitterMode
from whad.protocol.unifying.unifying_pb2 import \
    Sniff as UnifyingSniff, \
    Send as UnifyingSend, \
    Start as UnifyingStart, \
    Stop as UnifyingStop, \
    SetNodeAddress as UnifyingSetNodeAddress, \
    LogitechDongleMode as UnifyingLogitechDongleMode, \
    LogitechMouseMode as UnifyingLogitechMouseMode, \
    LogitechKeyboardMode as UnifyingLogitechKeyboardMode
import socket
import select
import re
import os
from struct import unpack, pack
import logging
logger = logging.getLogger(__name__)


class QEMURadioDevice(VirtualDevice):
    """This virtual device allows to emulate a radio link with a QEMU emulated nRF51/52 device,
    using a UNIX socket to receive and transmit packets.

    The UNIX socket must be spawned by QEMU before instantiation of this device, using
    the following naming convention: qemu_radio_<random>.sock
    """

    INTERFACE_NAME = "qemu"


    @classmethod
    def list(cls):
        '''
        Returns a list of available Unix socket devices matching the naming convention.
        '''
        devices = []

        try:
            # Read /proc/net/unix (Linux only)
            proc_net_unix = open('/proc/net/unix','r').read()

            # Extract all Unix sockets names, only keep those following the WHAD pattern:
            # *qemu_radio*.sock
            p = re.compile('^[0-9a-f]+: [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ [0-9]+ (.*)$', re.I | re.M)
            for socket in p.findall(proc_net_unix):
                _, filename = os.path.split(socket)
                if re.match('qemu_radio_[0-9a-f]+\.sock', filename):
                    dev = QEMURadioDevice(socket)
                    devices.append(dev)
            return devices
        except IOError as err:
            # Not supported, cannot enumerate devices
            return devices


    def __init__(self, path=None):
        """
        Create device connection
        """
        super().__init__()

        # Connect to target Unix Socket device in non-blocking mode
        self.__path = path
        self.__socket = None
        self.__client = None
        self.__opened = False
        self.__input_buffer = b""
        self.__active_domain = QEMUNrfDomains.QEMU_RAW_ESB
        self.__current_channel = 0
        self.__auto_skip = True
        super().__init__()

    @property
    def identifier(self):
        '''
        Returns the identifier of the device (e.g., socket path).
        '''
        return self.__path


    def open(self):
        """
        Open device.
        """
        if not self.__opened:
            # Open Unix socket
            self.__socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.__socket.connect(self.__path)
            self.__fileno = self.__socket.fileno()
            self.__opened = True

            self.__process_packet_flow = False

            self._dev_id = self._get_serial_number()
            self._fw_author = self._get_manufacturer()
            self._fw_url = self._get_url()
            self._fw_version = self._get_firmware_version()
            self._dev_capabilities = self._get_capabilities()

            # Ask parent class to run a background I/O thread
            super().open()


    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Esb : (
                (WhadCapability.Sniff | WhadCapability.Inject | WhadCapability.SimulateRole),
                [
                    EsbSniff,
                    EsbSend,
                    EsbStart,
                    EsbStop,
                    EsbSetNodeAddress,
                    EsbPrimaryReceiverMode,
                    EsbPrimaryTransmitterMode
                ]
            ),
            WhadDomain.LogitechUnifying : (
                (WhadCapability.Sniff | WhadCapability.Inject | WhadCapability.SimulateRole),
                [
                    UnifyingSniff,
                    UnifyingSend,
                    UnifyingStart,
                    UnifyingStop,
                    UnifyingSetNodeAddress,
                    UnifyingLogitechMouseMode,
                    UnifyingLogitechKeyboardMode,
                    UnifyingLogitechDongleMode
                ]
            ),
        }
        return capabilities

    def _get_manufacturer(self):
        return ("nRF51 - QEMUlated").encode('utf-8')

    def _get_serial_number(self):
        return self.__path.encode('utf-8') + (b"\x00" * (16 -  len(self.__path)) if len(self.__path) >= 0 else b"")

    def _get_firmware_version(self):
        return (1, 0, 0)

    def _get_url(self):
        return "https://github.com/rmalmain/qemu".encode('utf-8')

    def reset(self):
        """Reset device.

        This method is not supported by this type of device.
        """
        pass


    def close(self):
        """
        Close current device.
        """
        logger.error('socket close')
        # Close underlying device.
        if self.__socket is not None:
            self.__socket.close()

        # Unlink socket path
        # TDB: Do we remove the socket or let QEMU handle this ?
        #if os.path.exists(self.__path):
        #    os.unlink(self.__path)

        # Clear fileno and status
        self.__fileno = None
        self.__opened = False

        # Ask parent class to stop I/O thread
        super().close()


    def write(self, data):
        """Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes data: Data to write
        :returns: number of bytes written to the device
        """
        logger.debug('sending data to unix socket: %s' % hexlify(data))
        if not self.__opened:
            raise WhadDeviceNotReady()

        nb_bytes_written = 0
        wlist = [self.__fileno]
        elist = [self.__fileno]
        readers,writers,errors = select.select(
            [],
            wlist,
            elist
        )

        if len(writers) > 0:
            nb_bytes_written = self.__socket.send(data)
        return nb_bytes_written

    def read(self):
        """Fetches data from the device, if there is any data to read. We call select()
        to make sure data is waiting to be read before reading it. Data is then sent to
        our parsing method through on_data_received() that will handle data reassembling
        and message parsing and dispatch.
        """
        try:
            if not self.__opened:
                raise WhadDeviceNotReady()

            rlist = [self.__fileno]
            wlist = []
            elist = [self.__fileno]

            readers,writers,errors = select.select(
                rlist,
                wlist,
                elist,
                1
            )

            # Handle incoming messages if any
            if len(readers) > 0:
                data = self.__socket.recv(1024)
                if len(data) > 0:
                    self.on_data_block_received(data)
                else:
                    logger.error('No data received from device')
                    raise WhadDeviceDisconnected()
        except ConnectionResetError as err:
            logger.error('Connection reset by peer')
        except Exception as err:
            raise WhadDeviceDisconnected()

    def change_transport_speed(self, speed):
        """Not supported by Unix socket devices.
        """
        pass

    def on_data_block_received(self, block):
        # We process everything even if we don't need it because we don't have sync
        self.__input_buffer += block
        print("Incoming block: ", block.hex())

        # do we have enough data for unpacking a header ?
        while len(self.__input_buffer) >= 14:
            freq, timestamp, length, skip, crc = unpack("IIIBB", self.__input_buffer[:14])
            # do we have enough data to build a full packet ?
            if len(self.__input_buffer) >= length:
                # if so, extract it from the input buffer
                packet = self.__input_buffer[14:14+length]
                # transfer it to on_packet_received if packet flow is processed
                if self.__process_packet_flow:
                    self.on_packet_received(
                        freq,
                        timestamp,
                        skip == 1,
                        crc == 1,
                        packet
                    )
                self.__input_buffer = self.__input_buffer[14+length:]
            else:
                # otherwise, don't alter the input buffer, keep it for the next execution,
                # and break the loop
                break

    def build_ota_packet(self, freq, timestamp, packet):
        return pack("IIIBB", freq, timestamp, len(packet),0,1) + bytes(packet)

    def build_skip(self):
        return pack("IIIBB", 0,0,0,1,0)

    def on_packet_received(self, freq, timestamp, skip, crc_validity, packet):
        if self.__active_domain == QEMUNrfDomains.QEMU_RAW_ESB:
            self._send_whad_esb_pdu(packet, timestamp=timestamp, channel=freq, crc_validity=crc_validity)
        elif self.__active_domain == QEMUNrfDomains.QEMU_UNIFYING:
            self._send_whad_unifying_pdu(packet, timestamp=timestamp, channel=freq, crc_validity=crc_validity)
        else:
            print("[i] unknown active domain, skipping message.")

    def _send_whad_esb_pdu(self, pdu, timestamp=None, channel=None, crc_validity=None):
        msg = Message()
        if channel is not None:
            self.__current_channel = channel
            msg.esb.raw_pdu.channel = channel
        if timestamp is not None:
            msg.esb.raw_pdu.timestamp = timestamp
        if crc_validity is not None:
            msg.esb.raw_pdu.crc_validity = crc_validity

        msg.esb.raw_pdu.address = pdu[:5]
        msg.esb.raw_pdu.pdu = pdu

        self._send_whad_message(msg)


    def _send_whad_unifying_pdu(self, pdu, timestamp=None, channel=None, crc_validity=None):
        msg = Message()
        if channel is not None:
            self.__current_channel = channel
            msg.unifying.raw_pdu.channel = channel
        if timestamp is not None:
            msg.unifying.raw_pdu.timestamp = timestamp
        if crc_validity is not None:
            msg.unifying.raw_pdu.crc_validity = crc_validity

        msg.unifying.raw_pdu.address = pdu[:5]
        msg.unifying.raw_pdu.pdu = pdu

        self._send_whad_message(msg)


    def _on_whad_esb_sniff(self, message):

        self.__active_domain = QEMUNrfDomains.QEMU_RAW_ESB
        self.__auto_skip = True
        self._send_whad_command_result(ResultCode.SUCCESS)

    def _on_whad_esb_start(self, message):
        self.__active_domain = QEMUNrfDomains.QEMU_RAW_ESB
        self.__process_packet_flow = True
        self._send_whad_command_result(ResultCode.SUCCESS)

    def _on_whad_esb_stop(self, message):
        self.__active_domain = QEMUNrfDomains.QEMU_RAW_ESB
        self.__process_packet_flow = False
        self._send_whad_command_result(ResultCode.SUCCESS)


    def _on_whad_unifying_sniff(self, message):
        self.__active_domain = QEMUNrfDomains.QEMU_UNIFYING
        self.__auto_skip = True
        self._send_whad_command_result(ResultCode.SUCCESS)
