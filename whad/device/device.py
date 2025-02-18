"""
WHAD main device interface module.

This module provides multiple classes to handle WHAD device communication,
including background threads.
"""
import logging
from binascii import hexlify
from time import time, sleep
from queue import Queue, Empty
from threading import Thread, Lock

# Whad imports
from whad.exceptions import UnsupportedDomain, WhadDeviceNotReady, \
    WhadDeviceNotFound, WhadDeviceDisconnected, WhadDeviceTimeout, \
    WhadDeviceError
from whad.helpers import message_filter

# WHAD protocol hub
from whad.hub import ProtocolHub
from whad.hub.message import AbstractPacket, AbstractEvent
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.discovery import InfoQueryResp, DomainInfoQueryResp, DeviceReady
from whad.hub.discovery import DeviceType
from whad.hub.generic.cmdresult import ResultCode

from whad.device.info import WhadDeviceInfo

logger = logging.getLogger(__name__)

class WhadDeviceInputThread(Thread):

    """WhadDevice I/O cancellable Thread.

    This thread runs in background and regularly calls the
    device read() method to fetch any incoming data.
    """

    def __init__(self, device, io_thread):
        super().__init__()
        self.__device = device
        self.__io_thread = io_thread
        self.__canceled = False

    def cancel(self):
        """
        Cancel current I/O task.
        """
        self.__canceled = True

    def run(self):
        """
        Main task, call device process() method until thread
        is canceled.
        """
        while not self.__canceled:
            try:
                self.__device.read()
                #logger.debug("[WhadDeviceInputThread::run()] Read data from device")
            except WhadDeviceNotReady:
                logger.debug("Device %s has just disconnected (device not ready)",
                              self.__device.interface)
                break
            except WhadDeviceDisconnected:
                logger.debug("Device %s has just disconnected (read returned None)",
                             self.__device.interface)
                break
        logger.info("Device IO thread canceled and stopped.")
        self.__io_thread.on_disconnection()
        logger.info("on_disconnection done.")

class WhadDeviceMessageThread(Thread):
    """Main device incoming message processing thread.

    This thread runs in background, retrieves every message
    sent by the WHAD device to the host and forwards them to the
    `process_messages()` callback.
    """

    def __init__(self, device):
        super().__init__()
        self.__device = device
        self.__canceled = False

    def cancel(self):
        """
        Cancel current I/O task.
        """
        self.__canceled = True

    def run(self):
        """
        Main task, call device process_messages() method until thread
        is canceled.
        """
        while not self.__canceled:
            self.__device.process_messages()

        # Finish processing remaining messages
        logger.debug("[WhadDeviceMessageThread] processing remaining messages ...")
        while self.__device.process_messages(timeout=.1):
            pass

        logger.info("Device message thread canceled and stopped, closing device %s.",
                    self.__device)
        self.__device.close()

class WhadDeviceIOThread:
    """Main device IO thread.

    This thread runs in background and is in charge of collecting
    incoming messages from a WHAD interface and sending pending messages
    to the WHAD interface.
    """

    def __init__(self, device):
        self.__device = device
        self.__input = WhadDeviceInputThread(device, self)
        self.__input.daemon = True
        self.__processing = WhadDeviceMessageThread(device)
        self.__processing.daemon = True
        self.__disconnected = False
        self.__alive = False

    def is_alive(self) -> bool:
        """Check if IO thread is still alive.
        """
        return self.__alive

    def cancel(self):
        """Cancel device IO management thread.
        """
        self.__input.cancel()
        self.__processing.cancel()

    def start(self):
        """Start device IO management thread.
        """
        logger.info("starting WhadDevice IO management thread ...")
        self.__input.start()
        self.__processing.start()
        logger.info("WhadDevice IO management thread up and running.")
        self.__alive = True

    def join(self):
        """Wait for device IO management thread to complete.
        """
        logger.info("waiting for WhadDevice IO management thread to finish ...")
        while not self.__disconnected:
            try:
                logger.info("Waiting for io thread ...")
                self.__input.join(1.0)
            except RuntimeError:
                logger.debug((
                    "RuntimeError raised while joining input thread, we may try"
                    " to wait for our thread to finish :/"))

            try:
                logger.info("Waiting for processing thread ...")
                self.__processing.join(1.0)
            except RuntimeError:
                logger.debug(("RuntimeError raised while joining processing thread,"
                              " we may try to wait for our thread to finish :/"))

        logger.info("WhadDevice IO management thread finished.")
        self.__alive = False
        if self.__device.opened:
            logger.info("Closing device due to IO termination.")
            self.__device.close()

    def on_disconnection(self):
        """Handle underlying device disconnection
        """
        logger.debug("[device::io_thread] Adapter has disconnected")
        self.__disconnected = True
        self.__input.cancel()
        #self.__device.close()
        self.__processing.cancel()


class WhadDevice:
    """
    WHAD Device interface class.

    This device class handles the device discovery process, every possible
    discovery and generic messages related to the device discovery. It MUST be
    inherited by device handling classes (such as the UartDevice class) in order
    to provide read/write capabilities.

    Inherited classes MUST only implement the following methods:

      * open(): will handle device opening/access
      * close(): will handle device closing
      * read() to read data from the device and send them to on_data_received()
      * write() to send data to the device

    All the message re-assembling, parsing, dispatching and background data reading
    will be performed in this class.
    """

    INTERFACE_NAME = None

    @classmethod
    def _get_sub_classes(cls):
        """
        Helper allowing to get every subclass of WhadDevice.
        """
        # List every available device class
        device_classes = set()
        for device_class in cls.__subclasses__():
            if device_class.__name__ == "VirtualDevice":
                for virtual_device_class in device_class.__subclasses__():
                    device_classes.add(virtual_device_class)
            else:
                device_classes.add(device_class)
        return device_classes

    @classmethod
    def create_inst(cls, interface_string):
        """
        Helper allowing to get a device according to the interface string provided.

        To make it work, every device class must implement:
            - a class attribute INTERFACE_NAME, matching the interface name
            - a class method list, returning the available devices
            - a property identifier, allowing to identify the device in a unique way

        This method should NOT be used outside of this class. Use WhadDevice.create instead.
        """

        if interface_string.startswith(cls.INTERFACE_NAME):
            identifier = None
            index = None
            if len(interface_string) == len(cls.INTERFACE_NAME):
                index = 0
            elif interface_string[len(cls.INTERFACE_NAME)] == ":":
                index = None
                try:
                    _, identifier = interface_string.split(":")
                except ValueError:
                    identifier = None
            else:
                try:
                    index = int(interface_string[len(cls.INTERFACE_NAME):])
                except ValueError:
                    index = None

            # Retrieve the list of available devices
            # (could be a list or a dict)
            available_devices = cls.list()

            # If the list of device is built statically, check before instantiation
            if available_devices is not None:
                if index is not None:
                    try:
                        # Try to retrieve a device based on the provided index
                        return available_devices[index]
                    except KeyError as exc:
                        raise WhadDeviceNotFound from exc
                    except IndexError as exc:
                        raise WhadDeviceNotFound from exc
                elif identifier is not None:
                    if isinstance(available_devices, list):
                        for dev in available_devices:
                            if dev.identifier == identifier:
                                return dev
                    elif isinstance(available_devices, dict):
                        for dev_id, dev in available_devices.items():
                            if dev.identifier == identifier:
                                return dev
                    raise WhadDeviceNotFound
                else:
                    raise WhadDeviceNotFound
            # Otherwise, check dynamically using check_interface
            else:
                formatted_interface_string = interface_string.replace(
                    cls.INTERFACE_NAME + ":",
                    ""
                )
                if cls.check_interface(formatted_interface_string):
                    return cls(formatted_interface_string)
                raise WhadDeviceNotFound

        else:
            raise WhadDeviceNotFound

    @classmethod
    def create(cls, interface_string):
        '''
        Allows to get a specific device according to the provided interface string.
        The interface string is formed as follow:

        "<device_type>[device_index][:device_identifier]"

        Examples:
            * Instantiating the first available UartDevice:
                "uart" or "uart0"

            * Instantiating the second available UartDevice:
                "uart1"

            * Instantiating an UartDevice linked to /dev/ttyACM0:
                "uart:/dev/ttyACM0"

            * Instantiating the first available UbertoothDevice:
                "ubertooth" or "ubertooth0"

            * Instantiating an UbertoothDevice with serial number
              "11223344556677881122334455667788":
                ubertooth:11223344556677881122334455667788
        '''
        device_classes = cls._get_sub_classes()

        device = None
        for device_class in device_classes:
            try:
                device = device_class.create_inst(interface_string)
                return device
            except WhadDeviceNotFound:
                continue

        raise WhadDeviceNotFound

    @classmethod
    def list(cls):
        '''
        Returns every available compatible devices.
        '''
        device_classes = cls._get_sub_classes()

        available_devices = []
        for device_class in device_classes:
            device_class_list = device_class.list()
            if device_class_list is not None:
                if isinstance(device_class_list, list):
                    for device in device_class_list:
                        available_devices.append(device)
                elif isinstance(device_class_list, dict):
                    for dev_id, device in device_class_list.items():
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
            return self.__class__.INTERFACE_NAME + str(self.index)

        # Interface is unknown
        return "unknown"

    @property
    def type(self):
        '''
        Returns the name of the class linked to the current device.
        '''
        return self.__class__.__name__


    @property
    def opened(self) -> bool:
        """Determine if the interface has already been opened

        :return: `True` if interface is already open, `False` otherwise
        :rtype: bool
        """
        return self.__opened

    def __init__(self, index: int = None):
        """Initialize a device

        Device index can be specified through the `index` argument, but keep
        in mind that this `index` argument, if used, must be passed for all
        devices of the same class in order not to mess up with numbering.
        Calling code will be in charge of keeping device indexes unique.

        :param index: Specifies the index of this device
        :type index: int
        """
        # Device information
        self.__info = None
        self.__discovered = False
        self.__opened = False
        self.__closing = False

        # Generate device index if not provided
        if index is None:
            self.inc_dev_index()
            self.__index = self.__class__.CURRENT_DEVICE_INDEX
        else:
            # Used by HCI devices to force index to match system names
            self.__index = index

        # Device connectors
        self.__connector = None

        # Device IO thread
        self.__io_thread = None

        # Default timeout for messages (5 seconds)
        self.__timeout = 5.0

        # Message queues
        self.__messages = Queue()
        self.__msg_queue = Queue()
        self.__mq_filter = None

        # Input pipes
        self.__inpipe = bytearray()

        # Create locks
        self.__lock = Lock()
        self.__tx_lock = Lock()

        # Protocol hub
        self.__hub = ProtocolHub(2)

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

    @classmethod
    def inc_dev_index(cls):
        """Inject and maintain device index.
        """
        if hasattr(cls, 'CURRENT_DEVICE_INDEX'):
            cls.CURRENT_DEVICE_INDEX += 1
        else:
            cls.CURRENT_DEVICE_INDEX = 0

    def lock(self):
        """Locks the pending output data buffer."""
        self.__lock.acquire()

    def unlock(self):
        """Unlocks the pending output data buffer."""
        self.__lock.release()

    def set_connector(self, connector):
        """
        Set this device connector.

        :param WhadDeviceConnector connector: connector to be used with this device.
        """
        self.__connector = connector

    ######################################
    # Device I/O operations
    ######################################

    def open(self):
        """
        Open device method. By default, creates a simple thread
        that will handle I/O in background. This requires the object
        to be ready for I/O operations when this method is called.

        This method MUST be overriden by inherited classes.
        """
        self.__io_thread = WhadDeviceIOThread(self)
        self.__io_thread.start()

        # Ask firmware for a reset
        try:
            logger.info("resetting device (if possible)")
            self.__opened = True
            self.reset()
        except Empty as err:
            # Device is unresponsive, does not seem compatible
            # Shutdown IO thread
            self.__io_thread.cancel()
            self.__io_thread.join()

            # Notify device not found
            raise WhadDeviceNotReady() from err

    def close(self):
        """
        Close device.

        This method MUST be overriden by inherited classes.
        """
        # Avoid recursion when closing
        if not self.__opened or self.__closing:
            logger.debug("exiting close() to avoid recursion")
            return

        logger.info("closing WHAD device")
        self.__closing = True

        # Cancel I/O thread if required
        if self.__io_thread is not None:
            if self.__io_thread.is_alive():
                self.__io_thread.cancel()

        # Send a NOP message to unlock process_messages()
        logger.debug("send NOP message")
        msg = self.hub.generic.create_verbose(b'')
        self.on_message_received(msg)
        logger.debug("NOP message sent")

        # Wait for the thread to terminate nicely.
        if self.__io_thread is not None:
            self.__io_thread.join()

        self.__opened = False
        self.__closing = False

        # Notify connector device has closed
        if self.__connector is not None:
            self.__connector.on_disconnection()

    def wait(self):
        """Wait for device IO management thread to stop.
        """
        logger.debug("[WhadDevice] waiting for background thread to gracefully stop")
        self.__io_thread.join()
        logger.debug("[WhadDevice] background threads stopped")

    def is_open(self):
        """Determine if the device has been opened or not.
        """
        return self.__opened

    def __write(self, data):
        """
        Sends data to the device.

        This is an internal method that SHALL NOT be used from inherited classes.
        """
        self.lock()
        logger.debug("sending %s to WHAD device %s", bytes(data), self.interface)
        self.write(bytes(data))
        self.unlock()

    def write(self, data: bytes) -> int:
        """Default write method. This implementation emulates a successful write,
        but classes inheriting from WhadDevice must subclass this method to provide
        their own implementation.

        :param data: Data to write to the WHAD interface
        :type data: bytes
        :return: Number of bytes effectively written to the interface
        :rtype: int
        """
        return len(data)

    def set_queue_filter(self, queue_filter=None):
        """Sets the message queue filter.

        :param filter: filtering function/lambda to be used by our message queue filter.
        """
        logger.debug("set queue filter: %s", queue_filter)
        self.__mq_filter = queue_filter

    def wait_for_single_message(self, timeout, msg_filter=None):
        """Configures the device message queue filter to automatically move messages
        that matches the filter into the queue, and then waits for the first message
        that matches this filter and returns it.
        """
        if filter is not None:
            self.set_queue_filter(msg_filter)

        # Wait for a matching message to be caught (blocking)
        return self.__msg_queue.get(block=True, timeout=timeout)


    def wait_for_message(self, timeout=None, filter=None, command=False):
        """
        Configures the device message queue filter to automatically move messages
        that matches the filter into the queue, and then waits for the first message
        that matches this filter and process it.

        This method is blocking until a matching message is received.

        :param int timeout: Timeout
        :param filter: Message queue filtering function (optional)
        """

        # Check if device is still opem
        if not self.__opened and self.__msg_queue.empty():
            raise WhadDeviceDisconnected()

        logger.debug("entering wait_for_message ...")
        if filter is not None:
            self.set_queue_filter(filter)

        start_time = time()

        while True:
            try:
                # Wait for a matching message to be caught (blocking)
                msg = self.__msg_queue.get(block=True, timeout=timeout)

                # If message does not match, dispatch.
                if not self.__mq_filter(msg):
                    self.dispatch_message(msg)
                    logger.debug("exiting wait_for_message ...")
                else:
                    logger.debug("exiting wait_for_message ...")
                    return msg
            except Empty as err:
                # Queue is empty, wait for a message to show up.
                if timeout is not None and (time() - start_time > timeout):
                    if command:
                        raise WhadDeviceTimeout("WHAD device did not answer to a command") from err

                    logger.debug("exiting wait_for_message ...")
                    return None

                sleep(0.001)



    def send_message(self, message, keep=None):
        """
        Serializes a message and sends it to the device, without waiting for an answer.
        Optionally, you can update the message queue filter if you need to wait for
        specific messages after the message sent.

        :param Message message: Message to send
        :param keep: Message queue filter function
        """
        logger.info("sending message %s to device <%s>", message, self.interface)

        # if `keep` is set, configure queue filter
        if keep is not None:
            logger.debug("send_message:set_queue_filter")
            self.set_queue_filter(keep)

        # Convert message into bytes
        raw_message = message.serialize()


        # Define header
        header = [
            0xAC, 0xBE,
            len(raw_message) & 0xff,
            (len(raw_message) >> 8) & 0xff
        ]

        # Send header followed by serialized message
        self.__write(header)
        self.__write(raw_message)


    def send_command(self, command, keep=None):
        """
        Sends a command and awaits a specific response from the device.
        WHAD commands usualy expect a CmdResult message, if `keep` is not
        provided then this method will by default wait for a CmdResult.

        :param Message command: Command message to send to the device
        :param keep: Message queue filter function (optional)
        :returns: Response message from the device
        :rtype: Message
        """
        with self.__tx_lock:

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
                # Retrieve the first message matching our filter.
                result = self.wait_for_message(self.__timeout, command=True)
            except WhadDeviceTimeout as timedout:
                # Forward exception
                raise timedout

        # Log message
        logger.debug("Command result: %s", result)

        return result


    def on_data_received(self, data):
        """
        Data received callback.

        This callback will process incoming messages, parse them
        and then forward to the message processing callback.

        :param bytes data: Data received from the device.
        """
        #logger.info("[WhadDevice] entering on_data_received()")
        logger.debug("[WhadDevice] received raw data from device <%s>: %s",
                     self.interface, hexlify(data))
        self.__inpipe.extend(data)
        while len(self.__inpipe) > 2:
            # Is the magic correct ?
            if self.__inpipe[0] == 0xAC and self.__inpipe[1] == 0xBE:
                # Have we received a complete message ?
                if len(self.__inpipe) > 4:
                    msg_size = self.__inpipe[2] | (self.__inpipe[3] << 8)
                    if len(self.__inpipe) >= (msg_size+4):
                        raw_message = self.__inpipe[4:4+msg_size]

                        # Parse received message with our Protocol Hub
                        msg = self.__hub.parse(bytes(raw_message))

                        # Forward message if successfully parsed
                        if msg is not None:
                            self.on_message_received(msg)

                        # Chomp
                        self.__inpipe = self.__inpipe[msg_size + 4:]
                    else:
                        break
                else:
                    break
            else:
                # Nope, that's not a header
                while len(self.__inpipe) >= 2:
                    if (self.__inpipe[0] != 0xAC) or (self.__inpipe[1] != 0xBE):
                        self.__inpipe = self.__inpipe[1:]
                    else:
                        break


    def dispatch_message(self, message):
        """Dispatches an incoming message to the corresponding callbacks depending on its
        type and content.

        :param Message message: Message to dispatch
        """
        logger.info("dispatching WHAD message ...")

        # Allows a connector to catch any message
        self.on_any_msg(message)

        # Forward to dedicated callbacks
        if message.message_type == "discovery":
            logger.info("message is about device discovery, forwarding to discovery handler")
            self.on_discovery_msg(message)
        elif message.message_type == "generic":
            logger.info("message is generic, forwarding to default handler")
            self.on_generic_msg(message)
            logger.info("on_generic_message called")
        else:
            domain = message.message_type
            if domain is not None:
                logger.info("message concerns domain `%s`, forward to domain-specific handler",
                            domain)
                self.on_domain_msg(domain, message)

    def on_message_received(self, message):
        """
        Method called when a WHAD message is received, dispatching.

        :param Message message: Message received
        """
        if self.__closing:
            return

        logger.debug(("[WhadDevice::on_message_received()][%s] "
                      "message received: %s"), self.interface, message)
        logger.debug(("[WhadDevice::on_message_received()][%s] "
                     "message queue filter: %s"), self.interface, self.__mq_filter)

        # If message queue filter is defined and message matches this filter,
        # move it into our message queue.
        if self.__mq_filter is not None and self.__mq_filter(message):
            logger.info("message does match current filter, save it for processing")
            self.__msg_queue.put(message, block=True)
            logger.info("message added to message queue")
        else:
            # Save message for background dispatch
            logger.info(("message does not match filter or no filter set, "
                         "save in default message queue"))
            self.__messages.put(message, block=True)
            logger.info("message added to default message queue")

    def process_messages(self, timeout=1.0) -> bool:
        """Process pending messages
        """
        result = False

        #if self.__closing:
        #    return

        # If no connector set, we cannot process messages, we keep them in
        # memory instead.
        if self.__connector is None:
            return False

        try:
            message = self.__messages.get(block=True, timeout=timeout)
            if message is not None:
                logger.debug("[process_messages] retrieved message %s", message)
                self.dispatch_message(message)
                result = True

            return result
        except Empty:
            return False

    ######################################
    # Any messages
    ######################################

    def on_any_msg(self, message):
        """This callback method is called when any message is received

        :param Message message: WHAD message received
        """
        logger.debug("on_any_msg")
        # Forward message to the connector, if any
        if self.__connector is not None:
            logger.debug("Forward message %s to connector %s",
                         message, self.__connector)
            self.__connector.on_any_msg(message)

    ######################################
    # Generic messages handling
    ######################################

    def on_generic_msg(self, message):
        """
        This callback method is called whenever a Generic message is received.

        :param Message message: Generic message received
        """
        # Handle generic result message
        if isinstance(message, CommandResult):
            if message.result_code == CommandResult.UNSUPPORTED_DOMAIN:
                logger.error("domain not supported by this device")
                raise UnsupportedDomain("")

        # Forward everything to the connector, if any
        if self.__connector is not None:
            logger.debug("Forward generic message %s to connector %s",
                         message, self.__connector)
            self.__connector.on_generic_msg(message)
        else:
            logger.debug("No connector registered, message lost")


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
                self.__info = WhadDeviceInfo(
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
        msg = self.hub.discovery.create_reset_query()
        return self.send_command(
            msg,
            message_filter(DeviceReady)
        )

    def change_transport_speed(self, speed):
        """Set device transport speed.

        Optional.
        """

    @property
    def device_id(self):
        """Return device ID
        """
        return self.__info.device_id

    @property
    def info(self) -> WhadDeviceInfo:
        """Get device info object

        :return: Device information object
        :rtype: WhadDeviceInfo
        """
        return self.__info

    ######################################
    # Upper layers (domains) handling
    ######################################

    def on_domain_msg(self, domain, message):
        """
        Callback method handling domain-related messages. Since this layer is not
        managed by the root WhadDevice class, forward it to the upper layer, the
        associated connector (if any).

        :param Domain domain: Target domain
        :param Message message: Domain-related message received
        """

        # Forward everything to the connector, if any
        if self.__connector is not None:

            # Check if message is a received packet
            if issubclass(message, AbstractPacket):
                # Convert message into packet
                packet = message.to_packet()
                if packet is not None:

                    # Report packet to monitors
                    self.__connector.monitor_packet_rx(packet)

                    # Forward to our connector
                    if self.__connector.is_locked():
                        # If we are locked, then add packet to our locked packets
                        self.__connector.add_locked_pdu(packet)
                    elif self.__connector.is_synchronous():
                        # If we are in synchronous mode, add packet as pending
                        self.__connector.add_pending_packet(packet)
                    else:
                        #logger.debug("[WhadDevice] on_domain_msg() for device %s: %s",
                        #             self.interface, message)
                        self.__connector.on_packet(packet)
            elif issubclass(message, AbstractEvent):
                # Convert message into event
                event = message.to_event()
                if event is not None:
                    # Forward to our connector
                    self.__connector.on_event(event)
            else:
                # Forward other messages to on_domain_msg() callback
                self.__connector.on_domain_msg(domain, message)
        return False

class VirtualDevice(WhadDevice):
    """
    AdapterDevice device class.
    """
    def __init__(self, index: int = None):
        self._dev_type = None
        self._dev_id = None
        self._fw_author = None
        self._fw_url = None
        self._fw_version = (0, 0, 0)
        self._dev_capabilities = {}
        self.__lock = Lock()
        super().__init__(index)

    def send_message(self, message, keep=None):
        """Send message to host.
        """
        with self.__lock:
            super().set_queue_filter(keep)
            self._on_whad_message(message)

    def _on_whad_message(self, message):
        """TODO: associate callbacks with classes ?
        """
        category = message.message_type
        message_type = message.message_name

        callback_name = f"_on_whad_{category}_{message_type}"
        if hasattr(self, callback_name) and callable(getattr(self, callback_name)):
            getattr(self, callback_name)(message)
        else:
            logger.info("unhandled message: %s", message)
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
