from whad.exceptions import RequiredImplementation, UnsupportedDomain
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
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

class WhadDeviceConnector(object):
    """
    Device connector.

    A connector creates a link between a device and a protocol controller.
    """

    def __init__(self, device=None):
        """
        Constructor.

        Link the device with this connector, and this connector with the
        provided device.
        """
        self.set_device(device)
        if self.__device is not None:
            self.__device.set_connector(self)
        

    def set_device(self, device=None):
        """
        Set device linked to this connector.
        """
        if device is not None:
            self.__device = device
    
    @property
    def device(self):
        return self.__device

    # Device interaction
    def send_message(self, message, filter=None):
        return self.__device.send_message(message, filter)

    def process(self, keep=None):
        return self.__device.process(keep)

    # Message callbacks
    def on_discovery_message(self, message):
        raise RequiredImplementation()

    def on_generic_message(self, message):
        raise RequiredImplementation()

    def on_domain_message(self, domain, message):
        raise RequiredImplementation()

    
class WhadDevice(object):
    """
    Device interface class.

    This device class handles the device discovery process, every possible
    discovery and generic messages related to the device discovery.
    """

    def __init__(self):
        # Device information
        self.__info = None
        self.__discovered = False

        # Device connector
        self.__connector = None

    def set_connector(self, connector):
        """
        Set this device connector.
        """
        self.__connector = connector

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

    def process(self, keep=None):
        """
        Process outgoing and incoming messages. This method must be called very
        regularly to send and receive messages to and from the target device.
        """
        raise RequiredImplementation()

    def on_discovery_msg(self, message):
        """
        Method called when a discovery message is received. If a connector has
        been associated with the device, forward this message to this connector.
        """
        if self.__connector is not None:
            self.__connector.on_discovery_msg(message)
        
    def on_generic_msg(self, message):
        """
        Method called when a generic message is received.
        """
        # Handle generic result message
        if message.WhichOneof('msg') == 'result':
            if message.result == ResultCode.UNSUPPORTED_DOMAIN:
                raise UnsupportedDomain()

        # Forward everything to the connector, if any
        if self.__connector is not None:
            self.__connector.on_generic_msg(message)

    def on_domain_msg(self, domain, message):
        """
        Forward to connector.

        This method MUST return True if message has been processed,
        False otherwise.
        """
        if self.__connector is not None:
            return self.__connector.on_domain_msg(domain, message)
        return False

    def on_message_received(self, message):
        """
        Method called when a WHAD message is received, dispatching.
        """
        if message.WhichOneof('msg') == 'discovery':
            self.on_discovery_msg(message.discovery)
        elif message.WhichOneof('msg') == 'generic':
            self.on_generic_msg(message.generic)
        else:
            domain = message.WhichOneof('msg')
            self.on_domain_msg(domain, getattr(message,domain))


    def send_discover_info_query(self, proto_version=0x0100):
        """
        Send a DeviceInfoQuery message and awaits for a DeviceInfoResp
        answer.
        """
        msg = Message()
        msg.discovery.info_query.proto_ver=proto_version
        return self.send_message(
            msg,
            message_filter('discovery', 'info_resp')
        )


    def send_discover_domain_query(self, domain):
        """
        Send a DeviceDomainQuery message and awaits for a DeviceDomainResp
        answer.
        """
        msg = Message()
        msg.discovery.domain_query.domain = domain
        return self.send_message(
            msg,
            message_filter('discovery', 'domain_resp')
        )

    def discover(self):
        """
        Performs device discovery (synchronously).

        Discovery process asks the device to provide its description, including
        its supported domains and associated capabilities. For each domain we
        then query the device and get the list of supported commands.
        """
        if not self.__discovered:
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
                
                # Mark device as discovered
                self.__discovered = True
            else:
                raise WhadDeviceNotReady()


from whad.device.uart import UartDevice
