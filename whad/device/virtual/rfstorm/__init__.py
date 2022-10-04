from usb.core import find, USBError, USBTimeoutError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.device.virtual.rfstorm.constants import RFStormId, RFStormCommands, \
    RFStormDataRate, RFStormEndPoints, RFStormInternalStates
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.esb.esb_pb2 import Sniff, Send, Start, Stop
from whad import WhadCapability, WhadDomain

from threading import Thread
from time import sleep

# Helpers functions
def get_rfstorm(id=0,bus=None, address=None):
    '''
    Returns a RFStorm USB object based on index or bus and address.
    '''
    devices = list(find(idVendor=RFStormId.RFSTORM_ID_VENDOR, idProduct=RFStormId.RFSTORM_ID_PRODUCT,find_all=True))
    if bus is not None and address is not None:
        for device in devices:
            if device.bus == bus and device.address == address:
                return (devices.index(device), device)
        # No device found with the corresponding bus/address, return None
        return None
    else:
        try:
            return (id, devices[id])
        except IndexError:
            return None


class RFStormDevice(VirtualDevice):

    INTERFACE_NAME = "rfstorm"

    @classmethod
    def list(cls):
        '''
        Returns a list of available RFStorm devices.
        '''
        available_devices = []
        for rfstorm in find(idVendor=RFStormId.RFSTORM_ID_VENDOR, idProduct=RFStormId.RFSTORM_ID_PRODUCT,find_all=True):
            available_devices.append(RFStormDevice(bus=rfstorm.bus, address=rfstorm.address))
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in format "<bus>-<address>").
        '''
        return str(self.__rfstorm.bus)+"-"+str(self.__rfstorm.address)


    def __init__(self, index=0, bus=None, address=None):
        """
        Create device connection
        """
        device = get_rfstorm(index,bus=bus,address=address)
        if device is None:
            raise WhadDeviceNotFound

        self.__opened = False
        self.__channel = 0
        self.__address = b"\xFF\xFF\xFF\xFF\xFF"
        self.__scanning = False
        self.__scanning_thread = None
        self.__internal_state = RFStormInternalStates.NONE
        self.__index, self.__rfstorm = device
        super().__init__()

    def reset(self):
        self.__rfstorm.reset()

    def open(self):
        try:
            self.__rfstorm.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("rfstorm")
            else:
                raise WhadDeviceNotReady()

        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self.__opened_stream = False
        self.__opened = True
        # Ask parent class to run a background I/O thread
        super().open()

    def _scan(self):
        self.__channel = 0
        while self.__scanning:
            print(self.__channel, self._rfstorm_set_channel(self.__channel))

            # quick autofind
            if self.__internal_state == RFStormInternalStates.PROMISCUOUS_SNIFFING:
                self.__channel = (self.__channel + 1) % 100
                print(self._rfstorm_set_channel(self.__channel))
                sleep(0.5)

            elif self.__internal_state == RFStormInternalStates.SNIFFING:
                for self.__channel in range(0, 100):
                    print(self._rfstorm_set_channel(self.__channel))
                    ack = self._rfstorm_transmit_payload(b"\x0f\x0f\x0f\x0f", 1, 1)
                    if ack:
                        break

                while self.__scanning:
                    pass
    def _get_serial_number(self):
        return bytes.fromhex(
                                "{:02x}".format(self.__rfstorm.bus)*8 +
                                "{:02x}".format(self.__rfstorm.address)*8
        )

    def _get_manufacturer(self):
        return "Marc Newlin (BastilleResearch)".encode('utf-8')


    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Esb : (
                                (WhadCapability.Sniff | WhadCapability.Inject | WhadCapability.SimulateRole),
                                [Sniff, Send, Start, Stop]
            )
        }
        return capabilities

    def _get_firmware_version(self):
        return (1, 0, 0)

    def _get_url(self):
        return "https://github.com/BastilleResearch/nrf-research-firmware".encode('utf-8')


    def close(self):
        """
        Close current device.
        """
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        self.__opened = False
        if self.__scanning_thread is not None:
            self.__scanning = False
            self.__scanning_thread.join()
    def _rfstorm_send_command(self, command, data=b"", timeout=200, no_response=False):
        data = [command] + list(data)
        self.__rfstorm.write(RFStormEndPoints.RFSTORM_COMMAND_ENDPOINT, data, timeout=timeout)
        if not no_response:
            response = self._rfstorm_read_response()
            #print(">", response.hex())
            return response
        else:
            return True

    def _rfstorm_read_response(self, timeout=200):
        return bytes(self.__rfstorm.read(RFStormEndPoints.RFSTORM_RESPONSE_ENDPOINT, self.__rfstorm.bMaxPacketSize0, timeout=timeout))

    def _rfstorm_check_success(self, data):
        return len(data) > 0 and data[0] > 0

    def _rfstorm_read_packet(self):
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_RECV)

    def _rfstorm_promiscuous_mode(self, prefix=b""):
        data = bytes([len(prefix)]) + prefix
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_PROMISCUOUS, data, no_response=True)

    def _rfstorm_generic_promiscuous_mode(self, prefix=b"", rate=RFStormDataRate.RF_2MBPS, payload_length=32):
        data = bytes([len(prefix), rate, payload_length]) + prefix
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_PROMISCUOUS_GENERIC, data, no_response=True)

    def _rfstorm_sniffer_mode(self, address=b""):
        data = bytes([len(address)]) + address
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_SNIFF, data, no_response=True)

    def _rfstorm_tone_mode(self):
            return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TONE)

    def _rfstorm_transmit_payload(self, payload, timeout=4, retransmits=15):
        data = bytes([len(payload), timeout, retransmits]) + payload
        return self._rfstorm_check_success(
            self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TRANSMIT, data)
        )

    def _rfstorm_transmit_payload_generic(self, payload, address=b"\x33\x33\x33\x33\x33"):
        data = bytes([len(payload), len(address)]) + payload + address
        return self._rfstorm_check_success(
            self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TRANSMIT_GENERIC, data)
        )

    def _rfstorm_transmit_ack_payload(self, payload):
        data = bytes([len(payload)]) + payload
        return self._rfstorm_check_success(
            self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TRANSMIT_ACK, data)
        )

    def _rfstorm_set_channel(self, channel):
        if channel < 0 or channel > 125:
            return False

        data = bytes([channel])
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_SET_CHANNEL, data, no_response=True)

    def _rfstorm_get_channel(self, channel):
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_GET_CHANNEL)[0]

    def _rfstorm_enable_lna(self):
        return self._rfstorm_check_success(
            self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_ENABLE_LNA)
        )

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()
        if self.__opened_stream:
            try:
                data = self._rfstorm_read_packet()
            except USBTimeoutError:
                data = b""
            if data is not None and len(data) > 1:
                print(data.hex())

    def _on_whad_esb_sniff(self, message):
        print(message)

        channel = message.channel
        show_acknowledgements = message.show_acknowledgements
        address = message.address

        self.__channel = channel

        if address == b"\xFF\xFF\xFF\xFF\xFF":
            self.__internal_state = RFStormInternalStates.PROMISCUOUS_SNIFFING
        else:
            self.__internal_state = RFStormInternalStates.SNIFFING
            self.__address = address[::-1]

        self._send_whad_command_result(ResultCode.SUCCESS)

    def _on_whad_esb_stop(self, message):
        if self.__scanning_thread is not None:
            self.__scanning = False
            self.__scanning_thread.join()
            self.__scanning_thread = None
            self.__opened_stream = False
        self._send_whad_command_result(ResultCode.SUCCESS)

    def _on_whad_esb_start(self, message):
        if self.__channel == 0xFF:
            if self.__scanning_thread is None:
                self.__scanning_thread = Thread(target=self._scan, daemon=True)
                self.__scanning = True
                self.__scanning_thread.start()
            success = True
        else:
            success = self._rfstorm_set_channel(self.__channel)

        if self.__internal_state == RFStormInternalStates.SNIFFING:
            success = success and self._rfstorm_sniffer_mode(self.__address)
        elif self.__internal_state == RFStormInternalStates.PROMISCUOUS_SNIFFING:
            success = success and self._rfstorm_promiscuous_mode()

        if success:
            self.__opened_stream = True
            self._send_whad_command_result(ResultCode.SUCCESS)
        else:
            self._send_whad_command_result(ResultCode.ERROR)
