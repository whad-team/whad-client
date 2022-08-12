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
        self.on_whad_message(message)

    def on_whad_message(self, message):
        message_type = message.WhichOneof('msg')
        if message_type == "discovery":
            self.on_whad_discovery_message(message)
        elif message_type == "ble":
            self.on_whad_ble_message(message)
        else:
            print(message)

    def on_whad_discovery_message(self, message):
        if is_message_type(message, "discovery", "info_query"):
            self.on_whad_info_query(message.discovery.info_query)
        elif is_message_type(message, "discovery", "domain_query"):
            self.on_whad_domain_query(message.discovery.domain_query)

    def on_whad_ble_message(self, message):
        pass

    def on_whad_info_query(self, message):
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
        self.send_whad_message(msg)

    def on_whad_domain_query(self, message):
        supported_commands = self._dev_capabilities[message.domain][1]
        msg = Message()
        msg.discovery.domain_resp.domain = message.domain
        msg.discovery.domain_resp.supported_commands = 0
        for command in supported_commands:
            msg.discovery.domain_resp.supported_commands |= (1 << command)
        self.send_whad_message(msg)


    def send_whad_message(self, message):
        #print("Transmitting whad message:")
        #print(message)
        self.on_message_received(message)

    def send_whad_command_result(self, code):
        msg = Message()
        msg.generic.cmd_result.result = code
        self.send_whad_message(msg)

from .ubertooth import UbertoothDevice
