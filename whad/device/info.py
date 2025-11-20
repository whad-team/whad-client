"""
WHAD device information module.

This module provides the `WhadDeviceInfo` class that stores all the information
about a compatible WHAD device.
"""
from typing import List, Optional
from packaging.version import parse

from whad.helpers import asciiz
from whad.hub import ProtocolHub

class DeviceInfo:
    """This class caches a device information related to its firmware, type,
    and supported domains and capabilities.

    :param DeviceInfoResp info_resp:  Whad message containing the device basic information.
    """

    @staticmethod
    def create(proto_ver: int = 2, max_speed: int = 115200, author: str = '', url: str = '',
               version: str = '0.0', dev_type: int = 0, dev_id: bytes = b'',
               capabilities: Optional[List[int]] = None) -> 'DeviceInfo':
        # Parse version string
        ver = parse(version)

        # Build an InfoQueryResp message
        msg = ProtocolHub().discovery.create_info_resp(
            type=dev_type, device_id=dev_id, proto_min_ver=proto_ver, max_speed=max_speed,
            fw_author=author.encode('utf-8'), fw_url=url.encode('utf-8'),
            fw_version_major=ver.major, fw_version_minor=ver.minor, fw_version_rev=ver.micro,
            capabilities=capabilities
        )
        return DeviceInfo(msg)

    def __init__(self, info_resp):
        """Populate device information object from WHAD's InfoQueryResp message.

        :param info_resp: WHAD InfoQueryResp message
        :type info_resp: whad.hub.discovery.InfoQueryResp
        """
        # Store device information
        self.__whad_version = info_resp.proto_min_ver
        self.__max_speed = info_resp.max_speed
        self.__fw_author = info_resp.fw_author
        self.__fw_url = info_resp.fw_url
        self.__fw_ver_maj = info_resp.fw_version_major
        self.__fw_ver_min = info_resp.fw_version_minor
        self.__fw_ver_rev = info_resp.fw_version_rev
        self.__device_type = info_resp.type
        self.__device_id = asciiz(info_resp.device_id)

        # Parse domains and capabilities
        self.__domains = {}
        self.__commands = {}
        for domain in info_resp.capabilities:
            self.__domains[domain & 0xFF000000] = domain & 0x00FFFFFF
            self.__commands[domain & 0xFF000000] = 0

    def add_supported_commands(self, domain, commands):
        """Adds supported command for a given domain to the device information.

        :param domain: target domain
        :param commands: bitmask representing the supported commands for the given domain
        """
        if domain in self.__domains:
            self.__commands[domain] = commands


    def has_domain(self, domain):
        """Determine if a domain is supported by this device.

        :param Domain domain: Domain to check.
        :returns: True if supported, False otherwise.
        """
        return domain in self.__domains


    def has_domain_cap(self, domain, capability):
        """Check if device supports a specific capability for a given domain.

        :param Domain domain: target domain
        :param Capability capability: capability to check
        """
        if domain in self.__domains:
            return self.__domains[domain] & (1 << capability) > 0
        return False


    def get_domain_capabilities(self, domain):
        """Get device domain capabilities.

        :param Domain domain: target domain
        :returns: Domain capabilities
        :rtype: Bitmask of capabilities
        """
        if domain in self.__domains:
            return self.__domains[domain]
        return None


    def get_domain_commands(self, domain):
        """Get supported commands for a specific domain

        :param Domain domain: Target domain
        :returns: Bitmask of supported commands
        """
        if domain in self.__commands:
            return self.__commands[domain]
        return None


    ##### Getters #####

    @property
    def version_str(self):
        """Returns the device firmware version string.

        :returns: Device firmware version string
        """
        return f'{self.__fw_ver_maj:d}.{self.__fw_ver_min:d}.{self.__fw_ver_rev:d}'

    @property
    def whad_version(self):
        """Returns the device supported whad version.
        """
        return self.__whad_version

    @property
    def fw_author(self) -> str:
        """Get the device firmware author name.

        :return: Device's firmware author name
        :return-type: str
        """
        return self.__fw_author.decode("utf-8")

    @property
    def fw_url(self) -> str:
        """Get the device firmware URL

        :return: Firmware related URL
        :return-type: str
        """
        return self.__fw_url.decode("utf-8")

    @property
    def max_speed(self) -> int:
        """Get maximum communication speed.

        :return: Maximum communication speed
        :return-type: int
        """
        return self.__max_speed

    @property
    def device_type(self):
        """Returns the device type.
        """
        return self.__device_type

    @property
    def device_id(self):
        """Returns the device id.
        """
        return self.__device_id

    @property
    def domains(self) -> list[int]:
        """Return the list of supported domains.
        """
        return list(self.__domains.keys())
