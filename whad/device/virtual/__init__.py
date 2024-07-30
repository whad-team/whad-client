"""This module provides a VirtuaDevice class that can be used with a WhadDeviceConnector
to interact with a device that doesn't support WHAD protocol. It allows to convert WHAD messages
to the corresponding specific API calls.

This class handles device connection, disconnection and read/write operations. All the
parsing magic is performed in our WhadDevice class.
"""

from asyncio import QueueEmpty
import os
import select
from threading import Lock
from time import sleep
from queue import Empty

from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotReady
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter,is_message_type
from whad.protocol.device_pb2 import DeviceResetQuery,DeviceType
from whad.protocol.generic_pb2 import ResultCode
from whad.exceptions import WhadDeviceNotFound

import logging
logger = logging.getLogger(__name__)

class VirtualDevice(WhadDevice):
    """
    AdapterDevice device class.
    """
    def __init__(self):
        self._dev_type = None
        self._dev_id = None
        self._fw_author = None
        self._fw_url = None
        self._fw_version = None
        self._dev_capabilities = None
        self.__lock = Lock()
        super().__init__()

    def send_message(self, message, keep=None):
        self.__lock.acquire()
        super().set_queue_filter(keep)
        self._on_whad_message(message)
        self.__lock.release()

    def _on_whad_message(self, message):
        """TODO: associate callbacks with classes ?
        """
        category = message.message_type
        message_type = message.message_name

        callback_name = "_on_whad_"+category+"_"+message_type
        if hasattr(self, callback_name) and callable(getattr(self, callback_name)):
            getattr(self, callback_name)(message)
        else:
            logger.info("unhandled message: %s" % message)
            self._send_whad_command_result(ResultCode.ERROR)

    def _on_whad_discovery_info_query(self, message):
        major, minor, revision = self._fw_version
        msg = self.hub.discovery.create_info_resp(
            DeviceType.VirtualDevice,
            self._dev_id,
            0x0100,
            0,
            self._fw_author,
            self._fw_url,
            major, minor, revision,
            [domain | (capabilities[0] & 0xFFFFFF) for domain, capabilities in self._dev_capabilities.items()]
        )
        self._send_whad_message(msg)

    def _on_whad_discovery_domain_query(self, message):
        # Compute supported commands for domain
        commands = 0
        supported_commands = self._dev_capabilities[message.domain][1]
        for command in supported_commands:
            commands |= (1 << command)

        # Create a DomainResp message and send it
        msg = self.hub.discovery.create_domain_resp(
            message.domain,
            commands
        )
        self._send_whad_message(msg)


    def _send_whad_message(self, message):
        self.on_message_received(message)

    def _send_whad_command_result(self, code):
        msg = self.hub.generic.create_command_result(code)
        self._send_whad_message(msg)

from .ubertooth import UbertoothDevice
from .rzusbstick import RZUSBStickDevice
from .apimote import APIMoteDevice
from .hci import HCIDevice
from .rfstorm import RFStormDevice
from .yard import YardStickOneDevice
from .pcap import PCAPDevice
