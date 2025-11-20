"""WHAD Mock device for testing purpose.

This module provides a template class to design mock devices. Mock devices are
special devices intended to be used for unit testing, and should not be made
available to users.
"""
import logging
from threading import Thread, Event
from queue import Empty

from typing import Optional

from whad.hub import ProtocolHub
from whad.hub.message import HubMessage
from whad.hub.discovery import DeviceType

from ..device import Device, DeviceInfo, Disconnected, WhadDeviceDisconnected, \
    WhadDeviceNotReady

logger = logging.getLogger(__name__)

class MockInThread(Thread):
    """Internal thread processing data sent by the connector to the
    hardware interface.
    """

    def __init__(self, device: "MockDevice"):
        super().__init__()
        self.daemon = True
        self.__iface = device
        self.__canceled = False

    def cancel(self):
        """Cancel thread
        """
        self.__canceled = True

    def run(self):
        """Out thread main task.
        """
        while not self.__canceled:
            # Wait for a message to send to interface (blocking)
            logger.debug("[%s][in_thread] waiting for message to send", self.__iface.interface)
            try:
                with self.__iface.get_pending_message(timeout=1.0) as message:
                    # Read data from device (may block)
                    try:
                        logger.debug("[%s][in_thread] sending message %s",
                                     self.__iface.interface, message)

                        # Notify the device that we received a specific message from
                        # our connector:
                        self.__iface.on_connector_message(message)

                        # Notify message has correctly been sent, from a dedicated
                        # thread.
                        if message.has_callback():
                            Thread(target=message.sent).start()
                    except WhadDeviceNotReady:
                        if message.has_callback():
                            Thread(target=message.error, args=[1]).start()

                        # Exit processing loop
                        return
                    except WhadDeviceDisconnected:
                        if message.has_callback():
                            Thread(target=message.error, args=[2]).start()

                        # Exit processing loop
                        return
            except Empty:
                pass

class MockOutThread(Thread):
    """Internal thread processing data sent by the hardware interface
    to the device object.
    """

    def __init__(self, device: "MockDevice"):
        super().__init__()
        self.daemon = True
        self.__iface = device
        self.__canceled = False

    def cancel(self):
        """Cancel thread
        """
        self.__canceled = True

    def run(self):
        """Out thread main task.
        """
        while not self.__canceled:
            # Read data from device (may block)
            try:
                # Check if our mock device needs to fake a message sent by our
                # device.
                message = self.__iface.on_interface_message()
                if message is not None:
                    # Register message into the device queue
                    self.__iface.put_message(message)
            except WhadDeviceNotReady:
                break
            except WhadDeviceDisconnected:
                # Device has disconnected, notify interface by injecting a
                # `Disconnected` event message in its output message queue.
                # This event message will be filtered out by the Interface class
                # when called from our connector thread, and it will exit
                # gracefully
                logger.debug("[iface][%s] Device disconnected, sending event to connector.",
                             self.__iface.interface)
                self.__iface.put_message(Disconnected(self.__iface))
                break

class MockDevice(Device):
    """Mock device

    This device class is tied to no hardware and is intended to emulate the
    behavior of some real hardware device for a set of supported domains and
    features.
    """

    class route:
        """Mock device message routing decorator

        This decorator registered the decorated function as a callback for a
        specific message type.
        """

        def __init__(self, message_type):
            """Initialize decorator."""
            self.__msg_type = message_type

        def __call__(self, callback):
            """Called to decorate a specific callback"""
            setattr(callback, "_MESSAGE_TYPE", self.__msg_type)
            return callback


    # No interface to avoid instantiation
    INTERFACE_NAME = "mock"

    def __init__(self, author: str = 'whad', url: str = 'https://whad.io', proto_minver: int = 2,
                 version: str = '1.0', dev_type: int = DeviceType.VirtualDevice,
                 dev_id: bytes = b'', capabilities: Optional[dict] = None, max_speed: int = 115200,
                 index: Optional[int] = None):
        """Constructor."""
        # Loop over each method and registers those decorated with @route()
        self.__handlers = {}
        for prop_name in dir(self):
            try:
                prop_obj = getattr(self, prop_name)
                # If property is a method
                if callable(prop_obj) and hasattr(prop_obj, "_MESSAGE_TYPE"):
                    self.__handlers[getattr(prop_obj, "_MESSAGE_TYPE")] = prop_obj
            except AttributeError:
                pass

        # Set discovery properties
        self.__author = author
        self.__url = url
        self.__proto_minver = proto_minver
        self.__version = version
        self.__dev_type = dev_type
        self.__dev_id = dev_id
        self.__max_speed = max_speed
        self.__capabilities = capabilities or {}

        # Create a basic device
        super().__init__(index)

        # Custom device information management
        self.__info = None
        self.__iface_in = None
        self.__iface_out = None
        self.__hub = ProtocolHub()
        self.__discovered = False
        self.__opened = False

        # Waiting event
        self.__blocking_event = Event()

    @property
    def info(self) -> Optional[DeviceInfo]:
        """Device information object."""
        return self.__info

    @property
    def hub(self) -> ProtocolHub:
        """Retrieve the device protocol hub (parser/factory)
        """
        return self.__hub

    @property
    def opened(self) -> bool:
        """True if the mock device is open."""
        return self.__opened

    ##
    # Device operation
    ##

    def __start_io_threads(self):
        """Start background IO threads
        """
        self.__iface_in = MockInThread(self)
        self.__iface_in.start()
        self.__iface_out= MockOutThread(self)
        self.__iface_out.start()

    def __stop_io_threads(self):
        """Stop background IO threads
        """
        if self.__iface_in is not None:
            self.__iface_in.cancel()
            #self.__iface_in.join()
        if self.__iface_out is not None:
            self.__iface_out.cancel()
            #self.__iface_out.join()

    def open(self):
        """Open the mock device. We don't call Device.open() to avoid background
        threads to be created.
        """
        # Start background threads
        self.__start_io_threads()

        # Mark as opened
        self.__opened = True

        # Reset device
        self.reset()

    def reset(self) -> bool:
        """Reset device. We usually trigger a reset sequence and wait for a
        DeviceReady message.

        Override this method to implement a specific reset behavior.
        """
        return True

    def read(self) -> bytes:
        """Mock device does not emulate an hardware device by default, so read()
        is not supposed to be called.
        """
        logger.debug("[%s] unexpectedly reading bytes from interface.")
        return b""

    def write(self, payload: bytes) -> int:
        """Mock device does not emulate an hardware device by default, so write()
        is not supposed to be called.
        """
        logger.debug("[%s] unexpectedly writing bytes to interface: %s", self.interface,
                     payload.hex())
        return 0

    def close(self):
        """Close device.
        """
        # Stop io threads
        self.__stop_io_threads()

        # Mark device as closed
        self.__opened = False

        # Notify connector (if any) that the device has disconnected
        # Notify connector that device has closed
        if self.connector is not None:
            logger.debug("[%s] Send disconnection event to connector %s", self.interface,
                         self.connector)
            self.connector.send_event(Disconnected(self))
            logger.debug("[%s] Disconnection event sent !", self.interface)

    ##
    # Message hooks
    ##

    def on_connector_message(self, message: HubMessage):
        """Called whenever our output thread processes a message sent by a
        connector.

        :param message: Message to process
        :type message: HubMessage
        """
        # Do we have a haself.__handlers[type(message)]ndler registered for this specific message ?
        if type(message) in self.__handlers:
            logger.debug("[mock] Found handler associated with message type %s: %s", type(message), self.__handlers[type(message)])

            # Call message handler
            resp = self.__handlers[type(message)](message)

            # If handler returned a single message or a list of messages,
            # send them to the connector
            if isinstance(resp, HubMessage):
                self.put_message(resp)
            elif isinstance(resp, list):
                for m in resp:
                    if isinstance(m, HubMessage):
                        self.put_message(m)



    def on_interface_message(self) -> Optional[HubMessage]:
        """Called to check if the hardware interface needs to report something.
        This callback is mostly blocking by default, most of the processing
        using directly the device's `put_message` method to enqueue a message
        for the connector.

        However, it could be used to send notifications at a custom pace, if
        needed, depending on the subclass.
        """
        self.__blocking_event.wait()
        return None

    ##
    # Discovery management
    ##

    def discover(self):
        """Performs device discovery.

        Device discovered information is populated with the details provided
        when instantiating this device.
        """
        if not self.__discovered:
            # Convert capabilities dict into a domain/capabilities list
            caps = [ domain | cap[0] for domain, cap in self.__capabilities.items() ]

            # Create a new device information structure
            self.__info = DeviceInfo.create(
                author=self.__author,
                url=self.__url,
                version=self.__version,
                proto_ver=self.__proto_minver,
                max_speed=self.__max_speed,
                dev_type=self.__dev_type,
                dev_id=self.__dev_id,
                capabilities = caps
            )

            # Populate commands per domain
            for domain, cap in self.__capabilities.items():
                supp_commands = 0
                for cmd in cap[1]:
                    supp_commands = supp_commands | (1 << cmd)
                self.__info.add_supported_commands((domain&0xff000000), supp_commands)

            # Mark as discovered
            self.__discovered = True

        self.__hub = ProtocolHub(self.__proto_minver)

        # Set max transport speed
        if self.__info is not None:
            self.change_transport_speed(
                self.__info.max_speed
            )

    def get_domains(self) -> list[int]:
        """Get device' supported domains.

        :returns: list of supported domains
        :rtype: list
        """
        if self.__info is not None:
            return self.__info.domains

        # No domain discovered yet
        return []


    def get_domain_capability(self, domain):
        """Get a device domain capabilities.

        :param Domain domain: Target domain
        :returns: Domain capabilities
        :rtype: DeviceDomainInfoResp
        """
        if self.__info is not None:
            return self.__info.get_domain_capabilities(domain) or 0

        # No capability if not discovered
        return 0

    def get_domain_commands(self, domain):
        """Get a device supported domain commands.

        :param Domain domain: Target domain
        :returns: Bitmask of supported commands
        :rtype: int
        """
        if self.__info is not None:
            return self.__info.get_domain_commands(domain)

        # No supported commands by default
        return 0

    def has_domain(self, domain) -> bool:
        """Query device for domain support."""
        if self.__info is not None:
            return self.__info.has_domain(domain)
        return False

