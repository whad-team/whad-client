from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from whad import WhadDomain, WhadCapability
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.dot15d4 import Commands
from struct import unpack, pack
from time import sleep
from os.path import exists
import logging
logger = logging.getLogger(__name__)

class PCAPDevice(VirtualDevice):

    INTERFACE_NAME = "pcap"

    @classmethod
    def list(cls):
        '''
        Returns a list of available PCAP devices.
        '''
        return None

    @classmethod
    def check_interface(cls, interface):
        '''
        This method checks dynamically if the provided interface can be instantiated.
        '''
        logger.info("Checking interface: %s" % str(interface))
        if interface.endswith(".pcap") or interface.endswith(".pcapng"):
            return True
        else:
            return False

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in format "<bus>-<address>").
        '''
        return "pcap:" + str(self.__filename)


    def __init__(self, filename):
        """
        Create device connection
        """
        self.__opened = False
        self.__filename = filename
        super().__init__()

    def open(self):
        try:
            print("Opening:", self.__filename)
            if exists(self.__filename):
                logger.info("Existing PCAP file")
            else:
                logger.info("No PCAP file")
        except:
            raise WhadDeviceAccessDenied("pcap")

        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self.__opened = True
        # Ask parent class to run a background I/O thread
        super().open()

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()
        #self._send_whad_zigbee_raw_pdu(packet, rssi=rssi, is_fcs_valid=valid_fcs)

    def reset(self):
        pass

    def close(self):
        super().close()

    # Virtual device whad message builder
    def _send_whad_zigbee_raw_pdu(self, packet, rssi=None, is_fcs_valid=None, timestamp=None):
        '''
        pdu = packet[:-2]
        fcs = unpack("H",packet[-2:])[0]

        # Create a RawPduReceived message
        msg = self.hub.dot15d4.createRawPduReceived(
            self.__channel,
            pdu,
            fcs,
            fcs_validity=is_fcs_valid
        )

        # Set timestamp and RSSI if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        '''
        self._send_whad_message(msg)


    # Virtual device whad message callbacks
    def _on_whad_dot15d4_stop(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_send_raw(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_sniff(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_start(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Dot15d4 : (
                                (WhadCapability.Sniff | WhadCapability.Inject),
                                [Commands.Sniff, Commands.Send, Commands.Start, Commands.Stop]
            )
        }

        return capabilities

    def _get_manufacturer(self):
        return "whad-team".encode('utf-8')

    def _get_serial_number(self):
        return bytes.fromhex("00" * 16)

    def _get_firmware_version(self):
        return (0, 0, 0)

    def _get_url(self):
        return "https://github.com/whad-team/whad-client".encode('utf-8')
