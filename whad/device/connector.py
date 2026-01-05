"""
Connectors
----------

*Connectors* in WHAD are dedicated classes used to connect an *application*
to a WHAD compatible hardware (any compatible *device*) in order to provide
a set of features. We can see a *connector* as a role applied to a device,
usually related to a *domain* (or *wireless protocol*), that exposes methods
to perform various tasks that rely on a subset of commands supported by the
hardware.

*Connectors* shall ensure the device they are linked to does support the
target domain and a mimimal set of commands, and can tailor its behavior
depending on the capabilities of the hardware. If a *connector* is linked
to a device that either does not support the *domain* this *connector* is
supposed to operate or lacks specific *commands*, a
:py::class:`whad.exceptions.UnsupportedDomain` exception or a
:py:class:`whad.exceptions.UnsupportedCapability` may be raised.

Default connector features
~~~~~~~~~~~~~~~~~~~~~~~~~~

WHAD provides a default connector class, :py:class:`whad.device.connector.Connector`,
that implements a set of features out-of-the-box:

- Packet and message sniffing and processing
- Event notification mechanism
- Synchronous mode

Sniffing packet and messages could be useful to implement packet sniffers or
intercept some specific events like disconnection of the linked hardware device.
Most of the time this feature is used to sniff packets related to a target domain.
The :py:function:`whad.device.connector.Connector.sniff` method is specifically
tailored for this use. When not sniffing, packets received from the hardware device
are forwarded to the connector's packet processing methods than can be overriden by
inheriting classes.

By default, the default connector class provides methods to add and remove custom
event listeners (:py:function:`whad.device.connector.Connector.add_listener` and
:py:function:`whad.device.connector.Connector.remove_listener`), and an additional
method to send an event to the registered listeners (:py:function:`whad.device.connector.Connector.notify`).

Last but not least, the provided *synchronous mode* will disable packet forwarding
and save all received packets in a reception queue, waiting for the application to
retrieve and process them. Service messages will still be processed by the *connector*,
in order to handle any device disconnection or other unexpected event that may occur.
When this *synchronous mode* is disabled, every unprocessed packet stored in the
reception queue are automatically forwarded to the connector's packet processing
methods, and will be then dispatched to the corresponding handlers.
"""

import logging
import contextlib
from time import time
from queue import Queue, Empty
from threading import Thread, Lock, Event as ThreadEvent
from typing import Generator, Callable, Union, List, Optional

from scapy.packet import Packet

from whad.helpers import message_filter
from whad.hub import ProtocolHub
from whad.hub.message import AbstractPacket, AbstractEvent, HubMessage
from whad.hub.generic.cmdresult import CommandResult, Success
from whad.exceptions import WhadDeviceError, WhadDeviceDisconnected, \
    RequiredImplementation, UnsupportedDomain

from .device import Device, DeviceEvt, Disconnected, MessageReceived

logger = logging.getLogger(__name__)

class Event:
    """Generic connector event class.
    """

    def __str__(self):
        return "Event()"

    def __repr__(self):
        return "Event()"

class Notification:
    """Generic connector notification class."""

    def __str__(self) -> str:
        """String representation for notification."""
        return "Notification()"

    def __repr__(self) -> str:
        """Python representation."""
        return str(self)


class ConnIoThread(Thread):
    """Connector's background thread processing events from interface.

    This thread reads the associated connector's event queue and dispatch
    events to the `on_iface_event()` connector's method. Using a separate thread
    to process events sent by the interface avoids concurrency issues.
    """
    def __init__(self, connector: 'Connector'):
        """Connector thread intialization.

        :param connector: Connector associated with this I/O thread.
        :type connector: whad.device.connector.Connector
        """
        super().__init__()
        self.__connector = connector
        self.__canceled = False
        self.daemon = True

    def cancel(self):
        """Cancel IO thread"""
        self.__canceled = True

    def run(self):
        """Connector IO thread main task.
        """
        while not self.__canceled:
            try:
                # Retrieve pending event
                with self.__connector.get_event() as evt:
                    # Let connector process this message
                    self.__connector.on_device_event(evt)
            except Empty:
                pass

class Connector:
    """
    Interface connector.

    A connector creates a link between a device and a protocol controller.
    """

    # Synchronous modes
    SYNC_MODE_OFF = 0
    SYNC_MODE_PKT = 1
    SYNC_MODE_ALL = 2

    def __init__(self, device: Optional[Device] = None):
        """
        Constructor.

        Link the device with this connector, and this connector with the
        provided device.

        :param device: Device to be used with this connector.
        :type device: Device
        """
        self.__device = None
        self.set_device(device)
        if self.__device is not None:
            self.__device.set_connector(self)

        # Interface stall
        self.__stalled = False

        # Packet callbacks
        self.__callbacks_lock = Lock()
        self.__reception_callbacks = {}
        self.__transmission_callbacks = {}
        self.__error_callbacks = []

        # Connector lock mode
        self.__locked = False
        self.__locked_pdus = Queue()
        self.__lock = Lock()

        # Synchronous mode (not enabled by default)
        self.__sync_mode = Connector.SYNC_MODE_OFF

        # Synchronous events (device event + messages)
        self.__sync_events = Queue()

        # Queue holding events coming from our interface
        self.__events = Queue()

        # Create a background thread for message processing
        self.__io_thread = ConnIoThread(self)

        # Event listeners
        self.__listeners = []

        # Interface disconnection
        self.__disconnected = ThreadEvent()

        # Start background thread (start processing messages)
        self.__io_thread.start()


    def attach_error_callback(self, callback, context=None):
        '''Attach an error callback to this connector.

        :param callback: function handling errors.
        :param context:  context object to pass to the error handling function.
        :returns: Boolean indicating if the callback has been successfully attached.
        '''
        # add callbacks to error callbacks
        with self.__callbacks_lock:
            self.__error_callbacks.append(
                (callback, context)
            )

    def on_error(self, error):
        '''Triggers a call to the device connector error handling registered callback(s).
        '''
        if len(self.__error_callbacks) > 0:
            with self.__callbacks_lock:
                # Duplicate error callbacks list
                callbacks = list(self.__error_callbacks)

            # Call each error callback
            for callback, context in callbacks:
                callback(error, context=context)


    def attach_callback(self, callback, on_reception=True, on_transmission=True,
                        packet: Callable[[Packet], bool]=lambda pkt:True):
        """
        Attach a new packet callback to current connector.

        :param callback: Processing function.
        :param on_reception: Boolean indicating if the callback monitors reception.
        :param on_transmission: Boolean indicating if the callback monitors transmission.
        :param filter: Lambda function filtering packets matching the callback.
        :returns: Boolean indicating if the callback has been successfully attached.
        """
        with self.__callbacks_lock:
            callbacks_dicts = (
                ([self.__reception_callbacks] if on_reception else []) +
                ([self.__transmission_callbacks] if on_transmission else [])
            )
            for callback_dict in callbacks_dicts:
                callback_dict[callback] = packet

        return len(callbacks_dicts) > 0

    def detach_callback(self, callback, on_reception=True, on_transmission=True):
        """
        Detach an existing packet callback from current connector.

        :param callback: Processing function.
        :param on_reception: Boolean indicating if the callback was monitoring reception.
        :param on_transmission: Boolean indicating if the callback was monitoring transmission.
        :returns: Boolean indicating if the callback has been successfully detached.
        """
        # Enter critical section
        with self.__callbacks_lock:
            removed = False
            callbacks_dicts = (
                ([self.__reception_callbacks] if on_reception else []) +
                ([self.__transmission_callbacks] if on_transmission else [])
            )
            for callback_dict in callbacks_dicts:
                if callback in callback_dict:
                    del callback_dict[callback]
                    removed = True

        return removed

    def migrate_callbacks(self, connector):
        """Migrate callbacks to another connector
        """
        # Enter critical section
        with self.__callbacks_lock:
            for cb, cb_filter in self.__reception_callbacks.items():
                connector.attach_callback(
                    cb,
                    packet=cb_filter,
                    on_reception=True
                )
            self.__reception_callbacks = {}

            for cb, cb_filter in self.__transmission_callbacks.items():
                connector.attach_callback(
                    cb, packet=cb_filter, on_transmission=True
                )
            self.__transmission_callbacks = {}


    def reset_callbacks(self, reception = True, transmission = True):
        """
        Detach any packet callback attached to the current connector.

        :param on_reception: Boolean indicating if the callbacks monitoring
                             reception are detached.
        :param on_transmission: Boolean indicating if the callbacks monitoring
                                transmission are detached.
        """

        # Remove all callbacks
        with self.__callbacks_lock:
            if reception:
                self.__reception_callbacks = {}
            if transmission:
                self.__transmission_callbacks = {}


    def monitor_packet_tx(self, packet):
        """
        Signals the transmission of a packet and triggers execution of matching
        transmission callbacks.

        :param packet: scapy packet being transmitted from whad-client.
        """
        # Enter critical section
        with self.__callbacks_lock:
            for callback,packet_filter in self.__transmission_callbacks.items():
                if packet_filter(packet):
                    callback(packet)

    def monitor_packet_rx(self, packet):
        """
        Signals the reception of a packet and triggers execution of matching reception callbacks.

        :param packet: scapy packet being received by whad-client.
        """
        # Enter critical section
        with self.__callbacks_lock:
            for callback,packet_filter in self.__reception_callbacks.items():
                if packet_filter(packet):
                    callback(packet)

    def set_device(self, device=None):
        """
        Set device linked to this connector.

        :param WhadDevice device: Device to be used with this connector.
        """
        if device is not None:
            self.__device = device

    def mark_stalled(self):
        """Mark connector as stalled (pending disconnection)
        """
        self.__stalled = True


    def is_stalled(self) -> bool:
        """Determine if the interface associated with this connector is stalled,
        i.e. has messages awaiting processing even if closed.

        :return: True if interface is stalled, False otherwise.
        :rtype: bool
        """
        return self.__stalled

    @property
    def device(self):
        """Get the connector associated device instance
        """
        return self.__device

    @property
    def hub(self) -> ProtocolHub:
        """Get the connector protocol hub

        :return: Instance of ProtocolHub
        :rtype: ProtocolHub
        """
        return self.__device.hub

    def enable_synchronous(self, enabled : bool, events: bool = False):
        """Enable or disable synchronous mode

        Synchronous mode is a mode in which the connector expects sone third-party code to
        retrieve the received packets instead of forwarding them to the `on_packet()` callback.
        It is then possible to wait for some packet to be received and avoid the automatic
        behavior triggered by a call to `on_packet()`.

        :param enabled: If set to `True`, enable synchronous mode. Otherwise disable it.
        :type enabled: bool
        :param events: If set to `True`, synchronous mode will also capture events
                       sent by the associate device
        :type events: bool, optional
        """
        # Clear pending packets if we are disabling this feature.
        if not enabled and self.__sync_mode != Connector.SYNC_MODE_OFF:
            self.__sync_mode = Connector.SYNC_MODE_OFF
        elif enabled:
            if events:
                self.__sync_mode = Connector.SYNC_MODE_ALL
            else:
                self.__sync_mode = Connector.SYNC_MODE_PKT

        # Clear events queue
        self.__sync_events.queue.clear()

    def is_synchronous(self):
        """Determine if the conncetor is in synchronous mode.

        :return: `True` if synchronous mode is enabled, `False` otherwise.
        """
        return self.__sync_mode != Connector.SYNC_MODE_OFF

    def add_sync_event(self, event: DeviceEvt):
        """Add an event to the synchronous event queue when synchronous mode is
        enabled.

        :param event: Device event to add to our queue of received events
        :type event: whad.device.DeviceEvt
        """
        # Insert device events in synchronous event queue only if SYNC_MODE_ALL
        if isinstance(event, DeviceEvt) and self.__sync_mode == Connector.SYNC_MODE_ALL:
            self.__sync_events.put(event)
        elif isinstance(event, MessageReceived) and self.__sync_mode >= Connector.SYNC_MODE_PKT:
            # If SYNC_MODE_PKT is enabled, add MessageReceived event into our 
            # synchronous events queue
            self.__sync_events.put(event)

    def wait_packet(self, timeout:float = None):
        '''Wait for a packet when in synchronous mode. This method should be only used
        with SYNC_MODE_PKT to avoid discarding any device event.

        :param timeout: If specified, defines a timeout when querying the PDU queue
        :type timeout: float, optional
        :return: Received packet if any, None if empty or when timeout is reached
        :rtype: scapy.packet.Packet
        '''
        if self.__sync_mode >= Connector.SYNC_MODE_PKT:
            try:
                event = self.__sync_events.get(block=True, timeout=timeout)
                if isinstance(event, MessageReceived):
                    pkt = event.message.to_packet()
                    if pkt is not None:
                        return pkt
            except Empty:
                return None
        else:
            return None

    def lock(self):
        """Lock connector. A locked connector will not dispatch packets/pdus like
        in synchronous mode and will keep them in a waiting queue, but will dispatch
        them all at once when unlocked.
        """
        logger.info("[connector] lock()")
        self.__locked = True

        # Clear pending PDUs queue
        with self.__locked_pdus.mutex:
            self.__locked_pdus.queue.clear()

    def unlock(self, dispatch_callback=None):
        """Unlock connector and dispatch pending PDUs.

        :param  dispatch_callback: PDU dispatch callback that overrides the
                                   internal dispatch routine
        :type   dispatch_callback: callable
        """
        with self.__lock:
            logger.info("[connector][%s] unlock()", self.device.interface)
            # Dispatch PDUs
            try:
                # Loop until locked PDUs queue is empty
                while not self.__locked_pdus.empty():
                    # Retrieve PDU
                    message = self.__locked_pdus.get(block=True, timeout=0.2)
                    logger.debug("[connector][%s] Unlocked message for processing: %s",
                                self.device.interface, message)
                    if dispatch_callback is None:
                        logger.debug("[connector][%s] forward to __process_pkt_message()")
                        self.__process_pkt_message(message)
                    else:
                        # Call the provided dispatch callback
                        dispatch_callback(message)

                    # Mark locked PDU as processed
                    self.__locked_pdus.task_done()
            except Empty:
                logger.debug("[connector][%s] Processed all messages", self.device.interface)

        # Mark connector as unlocked
        self.__locked = False

    def is_locked(self) -> bool:
        """Determine if the connector is locked.

        :return: `True` if lock mode is enabled, `False` otherwise.
        """
        logger.info("[connector][%s] is_locked() -> %s", self.device.interface, self.__locked)
        return self.__locked

    def add_locked_pdu(self, pdu):
        """Add a pending Protocol Data Unit (PDU) to our locked pdus queue.

        :param  Packet pdu:  Packet to add to locked packets queue
        :type   pdu: scapy.packet.Packet
        """
        # We use the same lock used when unlocking to prevent adding more locked PDUs into
        # our locked PDUs queue, until it becomes full and connector is unlocked.
        with self.__lock:
            logger.info("[connector][%s] Add locked pdu: %s", self.device.interface, pdu)
            self.__locked_pdus.put(pdu)

    def has_locked_pdus(self) -> bool:
        """Determine if connector has locked PDUs.

        :return: `True` if connector has locked PDUs, `False` otherwise.
        :rtype: bool
        """
        return not self.__locked_pdus.empty()

    # Device interaction
    def send_message(self, message, keep=None):
        """Sends a message to the underlying device without waiting for an answer.

        :param Message message: WHAD message to send to the device.
        :param filter: optional filter function for incoming message queue.
        """
        try:
            logger.debug("sending WHAD message to device: %s", message)
            self.__device.send_message(message, keep)
        except WhadDeviceError as device_error:
            logger.debug("an error occurred while communicating with the WHAD device !")
            self.on_error(device_error)

    def send_command(self, message, keep=None):
        """Sends a command message to the underlying device and waits for an answer.

        By default, this method will wait for a CmdResult message, but you can provide
        any other filtering function/lambda if you are expecting another message as a
        reply from the device.

        :param Message message: WHAD message to send to the device
        :param filter: Filtering function used to match the expected response from the device.
        """
        try:
            return self.__device.send_command(message, keep=keep)
        except WhadDeviceError as device_error:
            logger.debug("an error occurred while communicating with the WHAD device !")
            self.on_error(device_error)
            return None

    ######################################
    # Packet flow handling
    ######################################

    def send_packet(self, packet):
        """Send packet to our device.
        """
        # Monitor this outgoing packet
        self.monitor_packet_tx(packet)

        # Convert packet into the corresponding message
        msg = self.hub.convert_packet(packet)

        if msg is not None:
            logger.info("[connector] send packet command")
            resp = self.send_command(msg, message_filter(CommandResult))
            logger.info("[connector] Command sent, result: %s", resp)

            # Do we have an error while sending this command ?
            if resp is None:
                # Report WHAD device as disconnected
                raise WhadDeviceDisconnected()

            # Check if command was successful
            return isinstance(resp, Success)

        # Cannot convert packet
        logger.error(("[connector] Packet cannot be converted into the"
                        "corresponding WHAD message"))
        return False


    def wait_for_message(self, timeout=None, keep=None, command=False):
        """Waits for a specific message to be received.

        This method reads the message queue and return the first message that matches the
        provided filter. A timeout can be specified and will cause this method to return
        None if this timeout is reached.
        """
        if self.__device is not None:
            return self.__device.wait_for_message(keep=keep, timeout=timeout, command=command)

    # Message callbacks
    def on_any_msg(self, message): # pylint: disable=W0613
        """Callback function to process any incoming messages.

        This method MAY be overriden by inherited classes.

        :param message: WHAD message
        """

    def on_discovery_msg(self, message): # pylint: disable=W0613
        """Callback function to process incoming discovery messages.

        This method MUST be overriden by inherited classes.

        :param message: Discovery message
        """
        logger.error("method `on_discovery_msg` must be implemented in inherited classes")
        raise RequiredImplementation()

    def on_generic_msg(self, message): # pylint: disable=W0613
        """Callback function to process incoming generic messages.

        This method MUST be overriden by inherited classes.

        :param message: Generic message
        """
        logger.error("method `on_generic_msg` must be implemented in inherited classes")
        raise RequiredImplementation()

    def on_domain_msg(self, domain, message): # pylint: disable=W0613
        """Callback function to process incoming domain-related messages.

        This method MUST be overriden by inherited classes.

        :param message: Domain message
        """
        logger.error("method `on_domain_msg` must be implemented in inherited classes")
        raise RequiredImplementation()


    def on_packet(self, packet): # pylint: disable=W0613
        """Callback function to process incoming packets.

        This method MUST be overriden by inherited classes.

        :param packet: Packet
        :type packet: :class:`scapy.packet.Packet`
        """
        logger.error("method `on_packet` must be implemented in inherited classes")
        raise RequiredImplementation()

    # TODO: event for device and connector event ?
    def on_event(self, event): # pylint: disable=W0613
        """Callback function to process incoming events.

        This method MUST be overriden by inherited classes.

        :param event: Event to process
        :type event: :class:`whad.hub.events.AbstractEvent`
        """
        logger.error("Class: %s", self.__class__)
        logger.error("method `on_event` must be implemented in inherited classes")
        raise RequiredImplementation()


    def send_event(self, event: DeviceEvt):
        """Send an event into the connector event queue.

        :param event: Event to add to the connector's event queue
        :type event: DeviceEvt
        """
        self.__events.put(event)

    def add_listener(self, listener: Callable[..., None],event_cls: Union[List[Event],
                                                                    Event] = None):
        """Add a connector notification listener with optional event filter.

        :param listener: callable to handle events
        :type listener: callable
        :param event_cls: List of event classes or single event class to match
        :type event_cls: list, ConnectorEvent, optional
        """
        if event_cls is not None:
            events = event_cls if isinstance(event_cls, list) else [event_cls]
        else:
            events = None
        self.__listeners.append((listener, events))

    def remove_listener(self, listener: Callable[..., None]) -> bool:
        """Remove listener from registered listeners.
        """
        # Find one or more entries related to the given listener
        items = set(filter(lambda x: x[0] == listener, self.__listeners))

        # Nothing found, return False
        if len(items) == 0:
            return False

        # Remove found entries.
        for item in items:
            self.__listeners.remove(item)

        # Success
        return True

    def clear_listeners(self):
        """Clear listeners.
        """
        self.__listeners = []

    def notify(self, event):
        """Notify listeners of a specific event.
        """
        for listener, events in self.__listeners:
            if events is None:
                listener(event)
            elif event.__class__ in events:
                listener(event)

    @contextlib.contextmanager
    def get_event(self, timeout: Optional[float] = None) -> Generator[DeviceEvt, None, None]:
        """Retrieve event from connector's event queue.

        :param timeout: Timeout in seconds
        :type timeout: float
        """
        try:
            yield self.__events.get(timeout=timeout)
        except Empty as err:
            raise err

        self.__events.task_done()

    def busy(self) -> bool:
        """Determine if this connector is busy.
        """
        # In synchronous mode, a busy connector has unprocessed events to
        # left in its events queue. If this events queue is empty, it is not considered
        # busy anymore.
        if self.__sync_mode != Connector.SYNC_MODE_OFF:
            return not self.__sync_events.empty()

        # If connector is locked or has unprocessed locked PDUs, it is considered busy.
        if not self.__locked_pdus.empty():
            return True

        # If not in synchronous mode, connector is busy if it still has events to
        # process (incoming messages) or if the associated interface has
        # messages to send
        return not self.__events.empty() or self.device.busy()

    def on_disconnection(self):
        """Device has disconnected or been closed.
        """
        logger.debug("[%s] interface has disconnected", self.device.interface)

        # Mark connector as disconnected
        self.__disconnected.set()

    def on_device_event(self, event: DeviceEvt):
        """Dispatch message to the connector's handlers.

        This method may trigger specific message processing in inherited
        connector's classes as well as attached protocol stacks. Since it
        is only called by the connector's I/O thread, that's pretty safe.

        :param event: Device event to process
        :type event: whad.device.DeviceEvt
        """
        # If synchronous mode is enabled and capturing all events, we simply
        # add these events to the synchronous mode event queue.
        if self.__sync_mode == Connector.SYNC_MODE_ALL:
            logger.debug("[synchronous] received event %s and save into sniffing queue", event)
            self.add_sync_event(event)
        else:
            # Did we receive a disconnection event ?
            if isinstance(event, Disconnected):
                logger.debug("[%s] received a disconnection message, processing ...",
                             self.device.interface)
                # Notify disconnection if we are not locked
                if self.is_locked():
                    logger.debug("[%s] locked, mark connector as stalled", self.device.interface)
                    self.mark_stalled()
                else:
                    logger.debug("[%s] not stalled, report disconnection", self.device.interface)
                    self.on_disconnection()

            # Or a hub emssage ?
            elif isinstance(event, MessageReceived):
                # If synchronous mode is enabled, add events into our synchronous
                # event queue. At this point in code, we are certain to be in
                # SYNC_MODE_PKT mode.
                if self.__sync_mode == Connector.SYNC_MODE_PKT:
                    self.add_sync_event(event)
                else:
                    # Process hub message if not in synchronous mode
                    self.process_message(event.message)

    # pylint: disable=C0301
    def sniff(self, messages: List = None, timeout: float = None) -> Generator[HubMessage, None, None]:
        """Enable sniffing mode and report any received messages, optionally
        filtered by their type/classes if `messages` is provided.

        :param messages: If specified, sniff only messages that match the given types.
        :param messages: List, optional
        :param timeout: If specified, set a sniffing timeout in seconds
        :type timeout: float, optional
        """
        # Enable sniffing mode (and disable message processing)
        self.enable_synchronous(True, events=True)

        # Listen for messages
        initial_to = timeout
        start_mark = time()
        while True:
            try:
                # Wait for an event
                event = self.__sync_events.get(block=True, timeout=timeout)
                logger.debug("[sniffer][%s] received event %s",
                                     self.device.interface, event)

                # If we received an event, process it
                if isinstance(event, Disconnected):
                    # Interface has disconnected, log this error and exit the function
                    logger.debug("[sniffer][%s] Interface has disconnected !",
                                    self.device.interface)
                    # Maybe raise an exception instead of simply exiting the sniff() method ?
                    # Calling code cannot tell if sniffing is just done or if an error occurred.
                    return

                if isinstance(event, MessageReceived):
                    logger.debug("[sniffer][%s] received message, processing",
                                     self.device.interface)
                    # Retrieve message
                    message = event.message

                    # Do we need to filter messages by type ?
                    if messages is not None:
                        logger.debug(
                            "[sniffer][%s] checking message type (%s) against filtered types (%s)",
                            self.device.interface, type(message), messages
                        )
                        if isinstance(message, messages):
                            yield message
                    else:
                        yield message

                # Notify queue we are done with this message
                self.__sync_events.task_done()

            except Empty:
                # We receive this exception when timeout has been reached when calling
                # our queue's get() method with a given timeout.
                logger.debug("[sniffer][%s] Sniffing timeout reached (%s seconds) !",
                             self.device.interface, initial_to)

            # If timeout is provided, compute remaining time and
            # exit loop when reached.
            if timeout is not None:
                timeout = timeout - (time() - start_mark)
                if timeout < 0:
                    break

        # Sniffing done, disable sniffing mode and return to normal operation
        self.enable_synchronous(False)

    def process_message(self, message: HubMessage):
        """Process received message.
        """
        logger.debug("[connector][%s] process_message() called for message %s", self.device.interface,
                     message)
        # Forward message to the on_any_msg() handler
        self.on_any_msg(message)

        # If message is of type "discovery", forward to our discovery
        # handler
        if message.message_type == "discovery":
            logger.info("message is about device discovery, forwarding to discovery handler")
            self.on_discovery_msg(message)
        elif message.message_type == "generic":
            # Handle generic result message
            if isinstance(message, CommandResult):
                if message.result_code == CommandResult.UNSUPPORTED_DOMAIN:
                    logger.error("domain not supported by this device")
                    raise UnsupportedDomain("")

            # Forward to generic message handler
            logger.info("message is generic, forwarding to default handler")
            self.on_generic_msg(message)
        else:
            domain = message.message_type
            if domain is not None:
                # Check if message is a received packet
                if issubclass(message, AbstractPacket):
                    # If connector is locked, save message into locked pdus
                    if self.is_locked():
                        self.add_locked_pdu(message)
                    else:
                        self.__process_pkt_message(message)
                # Check if message is a received event
                elif issubclass(message, AbstractEvent):
                    # Convert message into event
                    event = message.to_event()
                    if event is not None:
                        # Forward to our connector
                        self.on_event(event)

                # Other messages go to on_domain_msg
                else:
                    logger.info("message concerns domain `%s`, forward to domain-specific handler",
                                domain)
                    self.on_domain_msg(domain, message)

    def __process_pkt_message(self, message: HubMessage):
        """Process a Hub message containing a packet.

        :param message: Message supporting the AbstractPacket interface
        :type message: HubMessage
        """
        # Convert message into packet
        packet = message.to_packet()
        if packet is not None:
            self.monitor_packet_rx(packet)
            self.on_packet(packet)

    def join(self):
        """Wait for the interface to disconnect and messages to be processed.
        """
        self.__disconnected.wait()


class LockedConnector(Connector):
    """Provides a lockable connector.
    """

    def __init__(self, device):
        # We set the connector with no interface for now
        super().__init__(None)

        # Then we lock it
        self.lock()

        # And we eventually configure the interface
        # Once the device connector is set, packets will go in a locked queue
        # and could be later retrieved when connector is unlocked.
        self.set_device(device)
        device.set_connector(self)


class WhadDeviceConnector(Connector):
    """
    This class is an alias for :py:class:`whad.device.connector.Connector`,
    and will be deprecated in a near future. This class has been introduced
    in a previous version of WHAD and has been renamed for clarity purpose.
    """
