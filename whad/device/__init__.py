from whad.exceptions import RequiredImplementation, ResultUnsupportedDomain
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whacky_pb2 import Message
from whad.protocol.device_pb2 import DeviceType
from whad.helpers import message_filter

class WhadDeviceInfo(object):

    def __init__(self, info_resp):
        # Store device information
        self.__whad_version = info_resp.proto_min_ver
        self.__fw_ver_maj = info_resp.fw_version_major
        self.__fw_ver_min = info_resp.fw_version_minor
        self.__fw_ver_rev = info_resp.fw_version_rev
        self.__device_type = info_resp.type

        # Parse domains and capabilities
        self.__domains = {}
        self.__commands = {}
        for domain in info_resp.capabilities:
            self.__domains[domain & 0xFF000000] = domain & 0x00FFFFFF
            self.__commands[domain & 0xFF000000] = 0

    def add_supported_commands(self, domain, commands):
        if domain in self.__domains:
            self.__commands[domain] = commands

    @property
    def version_str(self):
        return '%d.%d.%d' % (
            self.fw_ver_maj,
            self.fw_ver_min,
            self.fw_ver_rev
        )

    @property
    def whad_version(self):
        return self.__whad_version
    
    @property
    def device_type(self):
        return self.__device_type

    @property
    def domains(self):
        return self.__domains.keys()

    def has_domain(self, domain):
        return domain in self.__domains

    def has_domain_cap(self, domain, capability):
        if domain in self.__domains:
            return (self.__domains[domain] & (1 << capability) > 0)
        return False

    def get_domain_capabilities(self, domain):
        if domain in self.__domains:
            return self.__domains[domain]
        return None

    def get_domain_commands(self, domain):
        if domain in self.__commands:
            return self.__commands[domain]
        return None

class WhadDevice(object):
    """
    Device interface class.
    """

    def __init__(self):
        # Device information
        self.__info = None

    def open(self):
        """
        Open device.
        """
        raise RequiredImplementation()

    def close(self):
        """
        Close device.
        """
        raise RequiredImplementation()

    def has_domain(self, domain):
        if self.__info is not None:
            return self.__info.has_domain(domain)

    def get_domains(self):
        if self.__info is not None:
            return self.__info.domains

    def get_domain_capability(self, domain):
        if self.__info is not None:
            return self.__info.get_domain_capabilities(domain)

    def get_domain_commands(self, domain):
        if self.__info is not None:
            return self.__info.get_domain_commands(domain)

    def send_message(self, message, filter=None):
        """
        Send a WHAD message to the device.

        @param message WHAD message to send
        @param filter  lambda function to filter the expected answer.
        """
        raise RequiredImplementation()

    def process(self, filter=None):
        """
        Process outgoing and incoming messages. This method must be called very
        regularly to send and receive messages to and from the target device.
        """

    def on_discovery_msg(self, message):
        """
        Method called when a discovery message is received.
        """
        raise RequiredImplementation()

    def on_generic_msg(self, message):
        """
        Method called when a generic message is received.
        """
        if message.WhichOneof('msg') == 'result':
            if message.result == ResultCode.UNSUPPORTED_DOMAIN:
                raise ResultUnsupportedDomain()

    def on_message_received(self, message):
        """
        Method called when a WHAD message is received, dispatching.
        """
        if message.WhichOneof('msg') == 'discovery':
            self.on_discovery_msg(message.discovery)
        elif message.WhichOneof('msg') == 'generic':
            self.on_generic_msg(message.generic)

    def on_discovery_msg(self, message):
        msg_type = message.WhichOneof('msg')
        if msg_type == 'info_resp':
            # Received a device info response
            # Loop on supported domains and ask for supported
            # commands
            for domain in message.info_resp.capabilities:
                self.get_domain_info(domain & 0xFF000000)
        elif msg_type == 'domain_resp':
            # Received a domain info response, update supported domain commands
            print(message.DESCRIPTOR.full_name)
            pass

    def send_discover_info_query(self, proto_version=0x0100):
        msg = Message()
        msg.discovery.info_query.proto_ver=proto_version
        return self.send_message(
            msg,
            message_filter('discovery', 'info_resp')
        )


    def send_discover_domain_query(self, domain):
        msg = Message()
        msg.discovery.domain_query.domain = domain
        return self.send_message(
            msg,
            message_filter('discovery', 'domain_resp')
        )

    def discover(self):
        """
        Performs device discovery.

        Discovery process asks the device to provide its description, including
        its supported domains and associated capabilities. For each domain we
        then query the device and get the list of supported commands.
        """
        # We send a DeviceInfoQuery message to the device and expect a
        # DeviceInfoResponse in return.
        resp = self.send_discover_info_query()

        # If we have an answer, process it.
        if resp is not None:
            # Save device information
            self.__info = WhadDeviceInfo(
                resp.discovery.info_resp
            )

            # Query device domains
            for domain in self.__info.domains:
                resp = self.send_discover_domain_query(domain)
                self.__info.add_supported_commands(
                    resp.discovery.domain_resp.domain,
                    resp.discovery.domain_resp.supported_commands
                )


from whad.device.uart import UartDevice

__all__ = ['WhadDevice', 'UartDevice']