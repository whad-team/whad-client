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
        super().__init__()

    def send_message(self, message, keep=None):
        # if `keep` is set, configure queue filter
        self.set_queue_filter(keep)
        self._on_whad_message(message)

    def _on_whad_message(self, message):
        category = message.WhichOneof('msg')
        message_type = getattr(message,category).WhichOneof('msg')

        callback_name = "_on_whad_"+category+"_"+message_type
        if hasattr(self, callback_name) and callable(getattr(self, callback_name)):
            inner_message = getattr(getattr(message,category), message_type)
            getattr(self, callback_name)(inner_message)
        else:
            logger.info("unhandled message: %s" % message)
            self._send_whad_command_result(ResultCode.ERROR)

    def _on_whad_discovery_info_query(self, message):
        msg = Message()
        msg.discovery.info_resp.type = DeviceType.VirtualDevice
        msg.discovery.info_resp.devid = self._dev_id
        msg.discovery.info_resp.proto_min_ver = 0x0100
        msg.discovery.info_resp.fw_author = self._fw_author
        msg.discovery.info_resp.fw_url = self._fw_url
        major, minor, revision = self._fw_version
        msg.discovery.info_resp.fw_version_major = major
        msg.discovery.info_resp.fw_version_minor = minor
        msg.discovery.info_resp.fw_version_rev = revision
        for domain, capabilities in self._dev_capabilities.items():
            msg.discovery.info_resp.capabilities.extend([domain | (capabilities[0] & 0xFFFFFF)])
        self._send_whad_message(msg)

    def _on_whad_discovery_domain_query(self, message):
        supported_commands = self._dev_capabilities[message.domain][1]
        msg = Message()
        msg.discovery.domain_resp.domain = message.domain
        msg.discovery.domain_resp.supported_commands = 0
        for command in supported_commands:
            msg.discovery.domain_resp.supported_commands |= (1 << command)
        self._send_whad_message(msg)


    def _send_whad_message(self, message):
        self.on_message_received(message)

    def _send_whad_command_result(self, code):
        msg = Message()
        msg.generic.cmd_result.result = code
        self._send_whad_message(msg)

from .ubertooth import UbertoothDevice
from .rzusbstick import RZUSBStickDevice
from .apimote import APIMoteDevice
from .hci import HCIDevice
from .rfstorm import RFStormDevice
