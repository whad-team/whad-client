"""
WHAD provides various classes to interact with WHAD-enabled hardware:

- :py:class:`whad.device.device.Device`
- :py:class:`whad.device.device.VirtualDevice`

Class :class:`whad.device.device.Device` is the default class that allows WHAD devices
enumeration and access. It is the main class to use to open any device, through
its :method:`whad.device.Device.create` method as shown below:

.. code-block:: python

    from whad.device import Device

    dev = Device.create("uart0")

The :py:class:`whad.device.device.VirtualDevice` shall not be directly used. This class
is used to add support for incompatible WHAD devices like the *Ubertooth*
or the *ApiMote* and acts as an adaptation layer between the underlying WHAD
protocol and the specific protocol used by the target hardware.

.. important::

    The :py:class:`whad.device.device.WhadDevice` class that is still defined in WHAD (and used
    in some old example scripts or documentation) is an alias for the new
    :py:class:`whad.device.Device` class, and is meant to be deprecated in the future.
    This old class has been renamed to ``Device`` for clarity, and the same happened
    with the old default connector class :py:class:`whad.device.connector.WhadConnector`
    that has been renamed to :py:class:`whad.device.connector.Connector`.

    These old classes will be marked as *deprecated* in a future release, with a
    specific EOL date announced. A warning message will be issued in case one of
    these classes is used in a script or a tool to give time to users to migrate
    to the new ones (renaming classes is enough to switch to the new implementation,
    APIs stay the same).

Default device classes
----------------------

.. autoclass:: whad.device.device.Device
    :members:

.. autoclass:: whad.device.device.VirtualDevice
    :show-inheritance:
    :members:

Old device classes to be deprecated in the future
-------------------------------------------------

.. autoclass:: whad.device.device.WhadDevice
    :show-inheritance:

.. autoclass:: whad.device.device.WhadVirtualDevice
    :show-inheritance:

"""
import re
import logging
import contextlib
from time import time
from typing import Generator, Callable, Union, Type, Optional
from threading import Thread, Lock
from queue import Queue, Empty

from packaging.version import Version

from whad.helpers import message_filter
from whad.exceptions import (
    WhadDeviceNotReady, WhadDeviceError, WhadDeviceTimeout, WhadDeviceDisconnected,
    WhadDeviceNotFound,
)
from whad.hub import ProtocolHub
from whad.hub.message import HubMessage
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.discovery import InfoQuery, InfoQueryResp, DomainInfoQuery, DomainInfoQueryResp, DeviceReady
from whad.hub.discovery import DeviceType

from .info import DeviceInfo

logger = logging.getLogger(__name__)

class DeviceEvt:
    """Device event.
    """
    def __init__(self, device: Optional['Device'] = None):
        self.__device = device

    @property
    def device(self) -> Optional['Device']:
        """Related device"""
        return self.__device

    def __repr__(self) -> str:
        """Printable representation of this event
        """
        iface = self.device.interface if self.device is not None else 'undefined'
        return f"DeviceEvt(iface='{iface}')"

class Disconnected(DeviceEvt):
    """Interface has disconnected.
    """
    def __repr__(self) -> str:
        """Printable representation of this event.
        """
        iface = self.device.interface if self.device is not None else 'undefined'
        return f"Disconnected(device='{iface}')"

class MessageReceived(DeviceEvt):
    """Message has been received.
    """
    def __init__(self, device = None, message = None):
        super().__init__(device)
        self.__message = message

    @property
    def message(self) -> Optional[HubMessage]:
        """Received message."""
        return self.__message

    def __repr__(self) -> str:
        """Printable representation of this event.
        """
        iface = self.device.interface if self.device is not None else 'undefined'
        return f"MessageReceived(device='{iface}')"

class DevInThread(Thread):
    """Internal thread processing data sent by the connector to the
    hardware interface.
    """

    def __init__(self, device = None):
        super().__init__(daemon=True)
        self.__iface = device
        self.__canceled = False

    def cancel(self):
        """Cancel thread
        """
        self.__canceled = True

    def serialize(self, message) -> bytes:
        """Serialize a WHAD message.
        """
        # Serialize protobuf message
        raw_msg = message.serialize()

        # Define header
        header = [
            0xAC, 0xBE,
            len(raw_msg) & 0xff,
            (len(raw_msg) >> 8) & 0xff
        ]

        # Build the final payload
        return bytes(header) + raw_msg

    def run(self):
        """Out thread main task.
        """
        while not self.__canceled:
            # Read data from device (may block)
            try:
                # Wait for a message to send to interface (blocking)
                logger.debug("[%s][in_thread] waiting for message to send", self.__iface.interface)
                with self.__iface.get_pending_message(timeout=1.0) as message:
                    logger.debug("[%s][in_thread] sending message %s",
                                 self.__iface.interface, message)

                    # Serialize message and send it.
                    payload = self.serialize(message)

                    # Send serialized message to interface
                    logger.debug("[%s][in_thread] acquiring lock on interface ...",
                                 self.__iface.interface)

                    self.__iface.lock()

                    logger.debug("[%s][in_thread] sending payload %s ...",
                                 self.__iface.interface, payload)
                    self.__iface.write(payload)
                    logger.debug("[%s][in_thread] releasing lock ...", self.__iface.interface)
                    self.__iface.unlock()

                    # Notify message has correctly been sent, from a dedicated
                    # thread.
                    if message.has_callback():
                        Thread(target=message.sent).start()
            except Empty:
                pass
            except WhadDeviceNotReady:
                if message.has_callback():
                    Thread(target=message.error, args=[1]).start()
                break
            except WhadDeviceDisconnected:
                if message.has_callback():
                    Thread(target=message.error, args=[2]).start()
                break

class DevOutThread(Thread):
    """Internal thread processing data sent by the hardware interface
    to the device object.
    """
    def __init__(self, device = None):
        super().__init__(daemon=True)
        self.__iface = device
        self.__canceled = False


        # Data processing
        self.__data = bytearray()

    def cancel(self):
        """Cancel thread
        """
        self.__canceled = True

    def ingest(self, data: bytes):
        """Ingest incoming bytes.
        """
        self.__data.extend(data)
        while len(self.__data) > 2:
            # Is the magic correct ?
            if self.__data[0] == 0xAC and self.__data[1] == 0xBE:
                # Have we received a complete message ?
                if len(self.__data) > 4:
                    msg_size = self.__data[2] | (self.__data[3] << 8)
                    if len(self.__data) >= (msg_size+4):
                        raw_message = self.__data[4:4+msg_size]

                        # Parse received message with our Protocol Hub
                        msg = self.__iface.hub.parse(bytes(raw_message))

                        # Forward message if successfully parsed
                        if msg is not None:
                            self.__iface.put_message(msg)

                        # Chomp
                        self.__data = self.__data[msg_size + 4:]
                    else:
                        break
                else:
                    break
            else:
                # Nope, that's not a header
                while len(self.__data) >= 2:
                    if (self.__data[0] != 0xAC) or (self.__data[1] != 0xBE):
                        self.__data = self.__data[1:]
                    else:
                        break

    def run(self):
        """Out thread main task.
        """
        while not self.__canceled:
            # Read data from device (may block)
            try:
                data = self.__iface.read()
                if data is not None:
                    self.ingest(data)
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
                return



class Device:
    """WHAD hardware interface
    """

    # Should be lowercase.
    INTERFACE_NAME = None

    @staticmethod
    def get_all_ifaces():
        """Load all known interfaces."""
        # Base transport
        from .uart import Uart
        from .hci import Hci
        from .tcp import TcpSocket
        from .unix import UnixSocket
        # Virtual transport
        from .apimote import Apimote
        from .pcap import Pcap
        from .rfstorm import RfStorm
        from .rzusbstick import RzUsbStick
        from .ubertooth import Ubertooth
        from .yard import YardStickOne
        return [
            Uart,
            Hci,
            TcpSocket,
            UnixSocket,
            Pcap,
            Apimote,
            RfStorm,
            RzUsbStick,
            Ubertooth,
            YardStickOne
        ]

    @classmethod
    def _get_sub_classes(cls):
        """
        Helper allowing to get every subclass of Device.
        """
        # List every available device class
        device_classes = set()
        for device_class in cls.__subclasses__():
            if device_class.__name__ in ("WhadVirtualDevice", "VirtualDevice"):
                for virtual_device_class in device_class.__subclasses__():
                    device_classes.add(virtual_device_class)
            else:
                device_classes.add(device_class)
        return device_classes

    @classmethod
    def create_inst(cls, interface_string) -> Type['Device']:
        """
        Helper allowing to get a device according to the interface string provided.

        To make it work, every device class must implement:
            - a class attribute INTERFACE_NAME, matching the interface name
            - a class method list, returning the available devices
            - a property identifier, allowing to identify the device in a unique way

        This method should NOT be used outside of this class. Use Device.create instead.
        """
        if cls.INTERFACE_NAME is None:
            raise WhadDeviceNotFound()

        logger.debug("Creating an instance of %s", interface_string)
        # Parses interface string, raise execption if format is incorrect
        pattern = r'^' + cls.INTERFACE_NAME + r'(:(?P<identifier>.*))?(?P<index>\d+)?$'
        result = re.match(pattern, interface_string)
        if result is None:
            raise WhadDeviceNotFound()

        # Extract interface identifier, if specified
        iface = result.groupdict()
        if iface['index'] is not None:
            iface_id = int(iface['index'])
        elif iface['identifier'] is not None:
            iface_id = iface['identifier']
        else:
            iface_id = None

        # Retrieve the list of available devices
        # and build a lookup dict
        interfaces = {}
        ifaces = cls.list()
        if isinstance(ifaces, list):
            for index, dev in enumerate(ifaces):
                interfaces[index] = dev
                interfaces[dev.identifier] = dev
        elif isinstance(ifaces, dict):
            for dev_id, dev in ifaces.items():
                interfaces[dev_id] = dev
                interfaces[dev.identifier] = dev
        else:
            interfaces = None

        # Some child classes may return None, in this case we need to use the
        # `check_interface()` to find the specified interface.
        if interfaces is None and iface_id is not None and cls.check_interface(iface_id):
            # Found, return an instance of this interface
            return cls(iface_id)

        if interfaces is not None and iface_id in interfaces:
            return interfaces[iface_id]

        if interfaces is not None and iface_id is None and 0 in interfaces and interfaces[0] is not None:
            return interfaces[0]

        # Return interface or raise an exception
        raise WhadDeviceNotFound()


    @classmethod
    def create(cls, interface_string):
        '''
        Create a specific device according to the provided interface string,
        formed as follows:

        <device_type>[device_index][:device_identifier]

        Examples:
            - `uart` or `uart0`: defines the first compatible UART device available
            - `uart1`: defines the second compatible UART device available
            - `uart:/dev/ttyACMO`: defines a compatible UART device identified
              by `/dev/tty/ACMO`
            - `ubertooth` or `ubertooth0`: defines the first available Ubertooth device
            - `ubertooth:11223344556677881122334455667788`: defines a Ubertooth
              device with serial number *11223344556677881122334455667788*
        '''
        # First try to find the corresponding device by calling find()
        device = Device.find(interface_string)
        if device is not None:
            return device

        # If not found, loop over all known interfaces
        device_classes = cls.get_all_ifaces()
        device = None
        for device_class in device_classes:
            logger.debug("trying class %s", device_class)
            try:
                device = device_class.create_inst(interface_string)
                return device
            except WhadDeviceNotFound:
                continue

        raise WhadDeviceNotFound

    @staticmethod
    def find(interface: str) -> Type['Device']:
        """Find a device based on its interface string with lazy loading of
        available interface implementations.

        :param interface: Interface name following WHAD's standard interface pattern
        :type  interface: str
        :return: Found interface object
        :rtype: Device
        :raise: WhadDeviceNotFound
        """
        # Based on selected transport, load the corresponding interface class.
        dev_info = re.match('^([^0-9:]+)([0-9]|:).*$', interface)
        if dev_info is not None:
            transport = dev_info.group(1).lower()
            # Basic interfaces using native transport
            if transport == 'uart':
                from .uart import Uart
                return Uart.create_inst(interface)
            elif transport == 'hci':
                from .hci import Hci
                return Hci.create_inst(interface)
            elif transport == 'tcp':
                from .tcp import TcpSocket
                return TcpSocket.create_inst(interface)
            elif transport == 'unix':
                from .unix import UnixSocket
                return UnixSocket.create_inst(interface)

            # Virtual interfaces using emulated transport
            elif transport == 'apimote':
                from .apimote import Apimote
                return Apimote.create_inst(interface)
            elif transport == 'pcap':
                from .pcap import Pcap
                return Pcap.create_inst(interface)
            elif transport == 'rfstorm':
                from .rfstorm import RfStorm
                return RfStorm.create_inst(interface)
            elif transport == 'rzusbstick':
                from .rzusbstick import RzUsbStick
                return RzUsbStick.create_inst(interface)
            elif transport == 'ubertooth':
                from .ubertooth import Ubertooth
                return Ubertooth.create_inst(interface)
            elif transport == 'yardstickone':
                from .yard import YardStickOne
                return YardStickOne.create_inst(interface)

            # No other known transport
            raise WhadDeviceNotFound


    @classmethod
    def list(cls) -> Union[list,dict]:
        '''
        Returns every available compatible devices.
        '''
        device_classes = cls.get_all_ifaces()

        available_devices = []
        for device_class in device_classes:
            device_class_list = device_class.list()
            if device_class_list is not None:
                if isinstance(device_class_list, list):
                    for device in device_class_list:
                        available_devices.append(device)
                elif isinstance(device_class_list, dict):
                    for _, device in device_class_list.items():
                        available_devices.append(device)
        return available_devices

    @classmethod
    def check_interface(cls, interface):
        '''
        Checks dynamically if the device can be instantiated.
        '''
        logger.debug("default: checking interface %s fails.", interface)
        return False

    @property
    def interface(self):
        '''
        Returns the current interface of the device.
        '''
        # If class has interface name, return the interface alias
        if hasattr(self.__class__,"INTERFACE_NAME"):
            if self.__class__.INTERFACE_NAME is not None:
                return self.__class__.INTERFACE_NAME + str(self.index)

        # Interface is unknown
        return "unknown"

    @property
    def type(self):
        '''
        Returns the name of the class linked to the current device.
        '''
        return self.__class__.__name__

    def __init__(self, index: Optional[int] = None):
        """Initialize an interface
        """
        # Interface state
        self.__info = None
        self.__opened = False
        self.__discovered = False

        # Generate device index if not provided
        if index is None:
            self.inc_dev_index()
            self.__index = self.__class__.CURRENT_DEVICE_INDEX
        elif isinstance(index, int):
            # Used by HCI devices to force index to match system names
            self.__index = index
        else:
            raise WhadDeviceNotFound()

        # IO Threads
        self.__iface_in = None
        self.__iface_out = None

        # Queue holding messages from connector, waiting to be sent to
        # the interface.
        self.__in_messages = Queue()

        # Queue holding messages from interface, waiting to be sent to
        # an attached connector
        self.__out_messages = Queue()

        # Connector bound to this device
        self.__connector = None

        # Interface lock
        self.__lock = Lock()
        # Connector lock
        self.__msg_filter: Callable[..., bool] = None

        # Protocol hub
        self.__hub = ProtocolHub()

        # Communication timeout
        self.__timeout = 5.0

    @contextlib.contextmanager
    def get_pending_message(self, timeout: float = None) -> Generator[HubMessage, None, None]:
        """Get message waiting to be sent to the interface.
        """
        try:
            yield self.__in_messages.get(timeout=timeout)
        except Empty as err:
            raise err

        # Mark task done
        self.__in_messages.task_done()

    @property
    def connector(self):
        """Connector bound to the interface
        """
        return self.__connector

    @property
    def hub(self):
        """Retrieve the device protocol hub (parser/factory)
        """
        return self.__hub

    @property
    def index(self) -> int:
        """Get the interface index

        :return: Interface index
        :rtype: int
        """
        return self.__index

    @property
    def device_id(self):
        """Return device ID
        """
        return self.__info.device_id

    @property
    def info(self) -> DeviceInfo:
        """Get device info object

        :return: Device information object
        :rtype: DeviceInfo
        """
        return self.__info

    @property
    def opened(self) -> bool:
        """Device is open ?
        """
        return self.is_open()

    def is_open(self) -> bool:
        """Determine if interface is opened.
        """
        return self.__opened

    @classmethod
    def inc_dev_index(cls):
        """Inject and maintain device index.
        """
        if hasattr(cls, 'CURRENT_DEVICE_INDEX'):
            cls.CURRENT_DEVICE_INDEX += 1
        else:
            cls.CURRENT_DEVICE_INDEX = 0

    def set_connector(self, connector):
        """Set interface connector.
        """
        self.__connector = connector

    def lock(self):
        """Lock interface for read/write operation.
        """
        self.__lock.acquire()
        logger.debug("Lock acquired !")

    def unlock(self):
        """Unlock interface for read/write operation.
        """
        logger.debug("Releasing lock ...")
        self.__lock.release()

    def _start_io_threads(self):
        """Start background IO threads
        """
        self.__iface_in = DevInThread(self)
        self.__iface_in.start()
        self.__iface_out= DevOutThread(self)
        self.__iface_out.start()

    def _stop_io_threads(self):
        """Stop background IO threads
        """
        if self.__iface_in is not None:
            self.__iface_in.cancel()
        if self.__iface_out is not None:
            self.__iface_out.cancel()

    ##
    # Device specific methods
    ##

    def open(self):
        """Handle device open
        """
        # Create interface I/O threads and start them.
        self._start_io_threads()

        # Ask interface for a reset
        try:
            logger.info("resetting interface (if possible)")
            self.__opened = True
            self.reset()
        except Empty as err:
            # Device is unresponsive, shutdown IO threads
            self._stop_io_threads()

            raise WhadDeviceNotReady() from err

    def read(self) -> bytes:
        """Read bytes from interface (blocking).
        """
        return b''

    def write(self, payload: bytes) -> int:
        """Write payload to interface.
        """
        return len(payload)

    def close(self):
        """Close device
        """
        logger.info("closing WHAD interface")

        # Cancel I/O thread if required
        self._stop_io_threads()
        self.__opened = False

        # Notify connector that device has closed
        if self.__connector is not None:
            logger.debug("Send disconnection event to connector %s", self.__connector)
            self.__connector.send_event(Disconnected(self))
            logger.debug("Disconnection event sent !")

    def change_transport_speed(self, speed):
        """Set device transport speed.

        Optional.
        """

    ##
    # Message processing
    ##

    def busy(self) -> bool:
        """Check if the interface is busy.

        We consider an interface as busy if there is at least one message in its
        output messages or in its input messages.
        """
        return not (self.__out_messages.empty() and self.__in_messages.empty())

    def set_queue_filter(self, keep: Callable[..., bool] = None):
        """Set message queue filter.
        """
        self.__msg_filter = keep

    def put_message(self, message: Union[HubMessage, DeviceEvt]):
        """Process incoming message.
        """
        # If no connector is attached to the interface, redirect to a dedicated
        # message queue. Same if the message is an interface event (this type of
        # messages MUST be handled by the interface itself).
        logger.debug("[%s] putting message %s", self.interface, message)
        if self.__connector is None:
            logger.debug("[%s] connector is None, sending to pending messages", self.interface)
            self.__out_messages.put(message)

        # If a connector is attached to the interface but a message filter
        # is set, redirect matching messages to a dedicated message queue
        # and notify the connector about the other messages, except if we
        # receive critical events from interface.
        elif isinstance(message, DeviceEvt):
            logger.debug("Sending event %s to connector %s", message, self.connector)
            self.connector.send_event(message)
        elif isinstance(message, HubMessage):
            # If a filter is set and message does not match, save it in our
            # pending messages queue.
            if self.__msg_filter is not None and self.__msg_filter(message):
                self.__out_messages.put(message)
            else:
                logger.debug("[%s] forwarding message to connector %s",
                             self.interface, self.connector)

                # Otherwise, wrap hub message into a `MessageReceived` event
                self.connector.send_event(MessageReceived(self, message))
        else:
            # Unknown message type, log it.
            logger.debug("[%s] put_message() called with an invalid parameter of type %s",
                         self.interface, type(message))

    def wait_for_single_message(self, timeout: float = None ,
                                keep: Callable[..., bool] = None):
        """Configures the device message queue filter to automatically move messages
        that matches the filter into the queue, and then waits for the first message
        that matches this filter and returns it.
        """
        unexpected_messages = []
        if keep is not None:
            self.set_queue_filter(keep)

        # Wait for a matching message to be caught (blocking)
        msg = self.__out_messages.get(block=True, timeout=timeout)

        # If message filter is set and message does not match, wait until an
        # expected message matches
        if keep is not None:
            # Wait for a matching message
            while not keep(msg):
                unexpected_messages.append(msg)
                msg = self.__out_messages.get(block=True, timeout=timeout)

            # Re-enqueue non-matching messages
            for m in unexpected_messages:
                self.__out_messages.put(m)
        return msg


    def wait_for_message(self, timeout: float = None, keep: Callable[..., bool] = None,
                         command: bool = False):
        """
        Configures the device message queue filter to automatically move messages
        that matches the filter into the queue, and then waits for the first message
        that matches this filter and process it.

        This method is blocking until a matching message is received.

        :param int timeout: Timeout
        :param filter: Message queue filtering function (optional)
        """

        # Raise a WhadDeviceDisconnected exception when the interface is still
        # considered opened but no messages to read in its output message queue.
        #
        # (This specific condition is met when a Unix client socket has closed
        # following a connection to a server, after the server sent a set of
        # messages that are still to process by the client).
        if not self.opened and self.__out_messages.empty():
            logger.debug("[%s] wait_for_message() cannot succeed because device is closed.")
            raise WhadDeviceDisconnected()

        if keep is not None:
            self.set_queue_filter(keep)

        start_time = time()

        while True:
            try:
                # Wait for a matching message to be caught (blocking)
                msg = self.__out_messages.get(block=True, timeout=timeout)

                # If we receive a disconnection event, raise an exception
                if isinstance(msg, Disconnected):
                    raise WhadDeviceDisconnected()

                # If message does not match, re-enqueue for late processing
                if not self.__msg_filter(msg):
                    self.put_message(msg)
                else:
                    # If it does match, return it
                    return msg
            except Empty as err:
                # Queue is empty, wait for a message to show up.
                if timeout is not None and (time() - start_time > timeout):
                    if command:
                        raise WhadDeviceTimeout("WHAD device did not answer to a command") from err

                    logger.debug("exiting wait_for_message (timeout: %s)...", timeout)
                    return None

    def send_message(self, message: HubMessage, keep: Callable[..., bool] = None):
        """
        Serializes a message and sends it to the interface, without waiting
        for an answer. Optionally, you can update the message queue filter
        if you need to wait for specific messages after the message is sent.

        :param Message message: Message to send
        :param keep: Message queue filter function
        """
        if not self.opened and self.__out_messages.empty():
            logger.debug("[%s] Cannot send message: device closed.", self.interface)
            raise WhadDeviceDisconnected()

        # Set message queue filter
        if keep is not None:
            self.set_queue_filter(keep)

        # Enqueue message to transmit to the interface
        self.__in_messages.put(message)


    def send_command(self, command: HubMessage, keep: Callable[..., bool] = None):
        """
        Sends a command and awaits a specific response from the device.
        WHAD commands usualy expect a CmdResult message, if `keep` is not
        provided then this method will by default wait for a CmdResult.

        :param Message command: Command message to send to the device
        :param keep: Message queue filter function (optional)
        :returns: Response message from the device
        :rtype: Message
        """
        # If a queue filter is not provided, expect a default CmdResult
        try:
            if keep is None:
                self.send_message(command, message_filter(CommandResult))
            else:
                self.send_message(command, keep)
        except WhadDeviceError as error:
            # Device error has been triggered, it looks like our device is in
            # an unspecified state, notify user.
            logger.debug("WHAD device in error while sending message: %s", error)
            raise error

        try:
            # Retrieve the first message that matches our filter
            result = self.wait_for_message(self.__timeout, command=True)
        except WhadDeviceTimeout as timedout:
            # Forward exception
            raise timedout

        # Log message
        logger.debug("Command result: %s", result)

        # Return command result
        return result


    ##
    # Interface management
    ##

    ######################################
    # Generic discovery
    ######################################

    def on_discovery_msg(self, message):
        """
        Method called when a discovery message is received. If a connector has
        been associated with the device, forward this message to this connector.
        """

        # Forward everything to the connector, if any
        if self.__connector is not None:
            self.__connector.on_discovery_msg(message)

    def has_domain(self, domain) -> bool:
        """Checks if device supports a specific domain.

        :param Domain domain: Domain
        :returns: True if domain is supported, False otherwise.
        :rtype: bool
        """
        if self.__info is not None:
            return self.__info.has_domain(domain)

        # No info available on device, domain is not supported by default
        return False


    def get_domains(self) -> dict:
        """Get device' supported domains.

        :returns: list of supported domains
        :rtype: list
        """
        if self.__info is not None:
            return self.__info.domains

        # No domain discovered yet
        return {}


    def get_domain_capability(self, domain):
        """Get a device domain capabilities.

        :param Domain domain: Target domain
        :returns: Domain capabilities
        :rtype: DeviceDomainInfoResp
        """
        if self.__info is not None:
            return self.__info.get_domain_capabilities(domain)

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


    def send_discover_info_query(self, proto_version=0x0100):
        """
        Sends a DeviceInfoQuery message and awaits for a DeviceInfoResp
        answer.
        """
        logger.info("preparing a DeviceInfoQuery message")
        msg = self.__hub.discovery.create_info_query(proto_version)
        return self.send_command(
            msg,
            message_filter(InfoQueryResp)
        )


    def send_discover_domain_query(self, domain):
        """
        Sends a DeviceDomainQuery message and awaits for a DeviceDomainResp
        answer.
        """
        logger.info("preparing a DeviceDomainInfoQuery message")
        msg = self.__hub.discovery.create_domain_query(domain)
        return self.send_command(
            msg,
            message_filter(DomainInfoQueryResp)
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

                # Ensure response is the one we expect
                assert isinstance(resp, InfoQueryResp)

                # Save device information
                self.__info = DeviceInfo(
                    resp
                )

                # Parse DeviceInfoResponse
                #device_info = self.hub.parse(resp)

                # Update our ProtocolHub version to the device version
                self.__hub = ProtocolHub(resp.proto_min_ver)

                # Query device domains
                logger.info("query supported commands per domain")
                for domain in self.__info.domains:
                    resp = self.send_discover_domain_query(domain)
                    self.__info.add_supported_commands(
                        resp.domain,
                        resp.supported_commands
                    )

                # Mark device as discovered
                logger.info("device discovery done")
                self.__discovered = True

                # Switch to max transport speed
                logger.info("set transport speed to %d", self.info.max_speed)
                self.change_transport_speed(
                    self.info.max_speed
                )
            else:
                logger.error("device is not ready !")
                raise WhadDeviceNotReady()

    def reset(self):
        """Reset device
        """
        logger.info("preparing a DeviceResetQuery message")
        msg = self.__hub.discovery.create_reset_query()
        return self.send_command(
            msg,
            message_filter(DeviceReady)
        )


class VirtDevInThread(Thread):
    """Internal thread processing data sent by the connector to the
    hardware interface.
    """

    def __init__(self, device: Device):
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

class VirtDevOutThread(Thread):
    """Internal thread processing data sent by the hardware interface
    to the device object.
    """

    def __init__(self, device):
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
                messages = self.__iface.read()
                if messages is not None:
                    if isinstance(messages, HubMessage):
                        # Register message into the device queue
                        self.__iface.put_message(messages)
                    elif isinstance(messages, list):
                        for msg in messages:
                            # Register message into the device queue
                            self.__iface.put_message(msg)
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



class VirtualDevice(Device):
    """
    Virtual interface implementation.

    This variant of the base Interface class provides a way to emulate an interface
    compatible with WHAD. This emulated compatible interface is used as an adaptation
    layer between WHAD's core and third-party hardware that does not run a WHAD-enabled
    firmware.
    """

    class route:
        """Virtual device message routing decorator

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

    def __init__(self, index: int = None):
        """Initialize a virtual device.

        :param index: Virtual device index
        :type  index: int
        """
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

        # Initialize our properties
        self.__dev_type = None
        self.__dev_id = None
        self.__fw_author = b''
        self.__fw_url = None
        self.__fw_version = (0, 0, 0)
        self.__capabilities = {}
        self.__lock = Lock()

        # Call parent class init.
        super().__init__(index)

    @property
    def dev_type(self) -> int:
        """Device type"""
        return self.__dev_type

    @dev_type.setter
    def dev_type(self, value: int):
        """Set device type."""
        self.__dev_type = value

    @property
    def dev_id(self) -> bytes:
        """Device ID"""
        return self.__dev_id

    @dev_id.setter
    def dev_id(self, value: bytes):
        """Set device ID"""
        self.__dev_id = value

    @property
    def author(self) -> str:
        """Firmware author name"""
        return self.__fw_author.decode('utf-8')

    @author.setter
    def author(self, name: str):
        """Set firmware author name"""
        self.__fw_author = name.encode('utf-8')

    @property
    def url(self) -> str:
        """Firmware URL"""
        return self.__fw_url.decode('utf-8')

    @url.setter
    def url(self, url: str):
        """Set firmware URL"""
        self.__fw_url = url.encode('utf-8')

    @property
    def version(self) -> tuple[int, int, int]:
        """Firmware version"""
        return self.__fw_version

    @version.setter
    def version(self, value: tuple[int, int, int]):
        """Set firmware version"""
        if not isinstance(value, tuple):
            raise ValueError()
        if len(value) != 3:
            raise ValueError()
        self.__fw_version = value

    @property
    def capabilities(self) -> dict[int, tuple[int, list[int]]]:
        """Device capabilities"""
        return self.__capabilities

    @capabilities.setter
    def capabilities(self, value: dict[int, tuple[int, list[int]]]):
        """Set device capabilities"""
        if not isinstance(value, dict):
            raise ValueError()
        self.__capabilities = value


    ##
    # Device operation
    ##

    def _start_io_threads(self):
        """Start background IO threads
        """
        self.__iface_in = VirtDevInThread(self)
        self.__iface_in.start()
        self.__iface_out= VirtDevOutThread(self)
        self.__iface_out.start()

    def _stop_io_threads(self):
        """Stop background IO threads
        """
        if self.__iface_in is not None:
            self.__iface_in.cancel()
        if self.__iface_out is not None:
            self.__iface_out.cancel()

    ##
    # Message hooks
    ##

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

    def on_connector_message(self, message: HubMessage):
        """Called whenever our output thread processes a message sent by a
        connector.

        :param message: Message to process
        :type message: HubMessage
        """
        # Do we have a haself.__handlers[type(message)]ndler registered for this specific message ?
        if type(message) in self.__handlers:
            logger.debug("[virtualdevice] Found handler associated with message type %s: %s", type(message), self.__handlers[type(message)])

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

    @route(InfoQuery)
    def on_info_query(self, msg: InfoQuery):
        """Process InfoQuery request."""
        major, minor, revision = self.__fw_version
        return self.hub.discovery.create_info_resp(
            DeviceType.VirtualDevice,
            self.__dev_id,
            (ProtocolHub.LAST_VERSION << 8),
            0,
            self.__fw_author,
            self.__fw_url,
            major, minor, revision,
            [dom | (cap[0] & 0xFFFFFF) for dom, cap in self.__capabilities.items()]
        )

    @route(DomainInfoQuery)
    def on_domain_query(self, msg: DomainInfoQuery):
        """Process DomainInfoQuery message."""
        # Compute supported commands for domain
        commands = 0
        supported_commands = self.__capabilities[msg.domain][1]
        for command in supported_commands:
            commands |= (1 << command)

        # Return a DomainResp message and send it
        return self.hub.discovery.create_domain_resp(
            msg.domain,
            commands
        )


class WhadDevice(Device):
    """
    This class is an alias for :py:class:`whad.device.device.Device`,
    and will be deprecated in a near future. This class has been introduced
    in a previous version of WHAD and has been renamed for clarity purpose.
    """

    @classmethod
    def create_inst(cls, interface_string):
        """Create an instance of interface from its name, using Device."""
        return Device.create_inst(interface_string)

    @classmethod
    def create(cls, interface_string):
        """Create an instance of interface from its name, using Device."""
        return Device.create(interface_string)        

    @classmethod
    def check_interface(cls, interface):
        """Check if Device supports the requested interface."""
        return Device.check_interface(interface)

class WhadVirtualDevice(VirtualDevice):
    """
    This class is an alias for :py:class:`whad.device.device.VirtualDevice`,
    and will be deprecated in a near future. This class has been introduced
    in a previous version of WHAD and has been renamed for clarity purpose.
    """

    @classmethod
    def create_inst(cls, interface_string):
        """Create an instance of interface from its name, using VirtualDevice."""
        return VirtualDevice.create_inst(interface_string)

    @classmethod
    def create(cls, interface_string):
        """Create an instance of interface from its name, using VirtualDevice."""
        return VirtualDevice.create(interface_string)        

    @classmethod
    def check_interface(cls, interface):
        """Check if VirtualDevice supports the requested interface."""
        return VirtualDevice.check_interface(interface)

