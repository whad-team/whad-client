"""
WHAD default device connector module.

This module provides a default connector class `WhadDeviceConnector` that
implements all the basic features of a device connector.
"""
import logging
import contextlib
from queue import Queue, Empty
from threading import Thread, Lock
from typing import Generator, Any, Callable, Union, List

from whad.helpers import message_filter
from whad.hub import ProtocolHub
from whad.hub.message import AbstractPacket, AbstractEvent
from whad.hub.generic.cmdresult import CommandResult, Success
from whad.exceptions import WhadDeviceError, WhadDeviceDisconnected, \
    RequiredImplementation, UnsupportedDomain
from whad.device.iface import Interface, IfaceEvt, Disconnected, MessageReceived

logger = logging.getLogger(__name__)

class WhadDeviceConnector:
    """
    Device connector.

    A connector creates a link between a device and a protocol controller.
    """

    def __init__(self, device=None):
        """
        Constructor.

        Link the device with this connector, and this connector with the
        provided device.

        :param device: Device to be used with this connector.
        :type device: WhadDevice
        """
        self.__device = None
        self.set_device(device)
        if self.__device is not None:
            self.__device.set_connector(self)

        # Packet callbacks
        self.__callbacks_lock = Lock()
        self.__reception_callbacks = {}
        self.__transmission_callbacks = {}
        self.__error_callbacks = []

        # Connector lock mode
        self.__locked = False
        self.__locked_pdus = Queue()

        # Synchronous mode (not enabled by default)
        self.__synchronous = False
        self.__pending_pdus = Queue()


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
                        filter=lambda pkt:True):
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
                callback_dict[callback] = filter

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
                    filter=cb_filter,
                    on_reception=True
                )
            self.__reception_callbacks = {}

            for cb, cb_filter in self.__transmission_callbacks.items():
                connector.attach_callback(
                    cb, filter=cb_filter, on_transmission=True
                )
            self.__transmission_callbacks = {}


    def reset_callbacks(self, reception = True, transmission = True):
        """
        Detach any packet callback attached to the current connector.

        :param on_reception: Boolean indicating if the callbacks monitoring
                             reception are detached.
        :param on_transmission: Boolean indicating if the callbacks monitoring
                                transmission are detached.
        :returns: Boolean indicating if callbacks have been successfully detached.
        """

        # Enter critical section
        with self.__callbacks_lock:
            callbacks_dicts = (
                ([self.__reception_callbacks] if reception else []) +
                ([self.__transmission_callbacks] if transmission else [])
            )
            for callback_dict in callbacks_dicts:
                callback_dict = {}

        return len(callbacks_dicts) > 0


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

    def enable_synchronous(self, enabled : bool):
        """Enable or disable synchronous mode

        Synchronous mode is a mode in which the connector expects sone third-party code to
        retrieve the received packets instead of forwarding them to the `on_packet()` callback.
        It is then possible to wait for some packet to be received and avoid the automatic
        behavior triggered by a call to `on_packet()`.

        :param enabled: If set to `True`, enable synchronous mode. Otherwise disable it.
        :type enabled: bool
        """
        # Clear pending packets if we are disabling this feature.
        if not enabled:
            self.__pending_pdus.queue.clear()

        # Update state
        self.__synchronous = enabled

    def is_synchronous(self):
        """Determine if the conncetor is in synchronous mode.

        :return: `True` if synchronous mode is enabled, `False` otherwise.
        """
        return self.__synchronous

    def add_pending_packet(self, pdu):
        """Add a pending protocol data unit (PDU) if in synchronous mode.

        :param pdu: Pending PDU to add to our queue of pending PDUs
        :type pdu: scapy.packet.Packet
        """
        if self.__synchronous:
            self.__pending_pdus.put(pdu)

    def wait_packet(self, timeout:float = None):
        '''Wait for a packet when in synchronous mode.

        :param timeout: If specified, defines a timeout when querying the PDU queue
        :type timeout: float, optional
        :return: Received packet if any, None otherwise
        :rtype: scapy.packet.Packet
        '''
        if self.__synchronous:
            try:
                return self.__pending_pdus.get(block=True, timeout=timeout)
            except Empty:
                return None
        else:
            return None

    def lock(self):
        """Lock connector. A locked connector will not dispatch packets/pdus like
        in synchronous mode and will keep them in a waiting queue, but will dispatch
        them all at once when unlocked.
        """
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
        # Dispatch PDUs
        try:
            while True:
                # Retrieve PDU
                message = self.__locked_pdus.get(block=False, timeout=0.2)
                logger.info("Unlocked message for processing: %s", message)
                if dispatch_callback is None:
                    self.device.on_packet_message(message)
                else:
                    # Call the provided dispatch callback
                    dispatch_callback(message)
        except Empty:
            logger.info("Error while unlocking")
            # Processing done, continue.
            pass

        # Mark connector as unlocked
        self.__locked = False

    def is_locked(self) -> bool:
        """Determine if the connector is locked.

        :return: `True` if lock mode is enabled, `False` otherwise.
        """
        return self.__locked

    def add_locked_pdu(self, pdu):
        """Add a pending Protocol Data Unit (PDU) to our locked pdus queue.

        :param  Packet pdu:  Packet to add to locked packets queue
        :type   pdu: scapy.packet.Packet
        """
        logger.info("Add locked pdu: %s", pdu)
        self.__locked_pdus.put(pdu)

    # Device interaction
    def send_message(self, message, filter=None):
        """Sends a message to the underlying device without waiting for an answer.

        :param Message message: WHAD message to send to the device.
        :param filter: optional filter function for incoming message queue.
        """
        try:
            logger.debug("sending WHAD message to device: %s", message)
            self.__device.send_message(message, filter)
        except WhadDeviceError as device_error:
            logger.debug("an error occured while communicating with the WHAD device !")
            self.on_error(device_error)

    def send_command(self, message, filter=None):
        """Sends a command message to the underlying device and waits for an answer.

        By default, this method will wait for a CmdResult message, but you can provide
        any other filtering function/lambda if you are expecting another message as a
        reply from the device.

        :param Message message: WHAD message to send to the device
        :param filter: Filtering function used to match the expected response from the device.
        """
        try:
            return self.__device.send_command(message, filter)
        except WhadDeviceError as device_error:
            logger.debug("an error occured while communicating with the WHAD device !")
            self.on_error(device_error)
            return None

    def on_disconnection(self):
        """Device has disconnected or been closed.
        """


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


    def wait_for_message(self, timeout=None, filter=None, command=False):
        """Waits for a specific message to be received.

        This method reads the message queue and return the first message that matches the
        provided filter. A timeout can be specified and will cause this method to return
        None if this timeout is reached.
        """
        return self.__device.wait_for_message(timeout=timeout, filter=filter, command=command)

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

    def on_event(self, event): # pylint: disable=W0613
        """Callback function to process incoming events.

        This method MUST be overriden by inherited classes.

        :param event: Event to process
        :type event: :class:`whad.hub.events.AbstractEvent`
        """
        logger.error("Class: %s", self.__class__)
        logger.error("method `on_event` must be implemented in inherited classes")
        raise RequiredImplementation()


class LockedConnector(WhadDeviceConnector):
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


class ConnIoThread(Thread):
    """Connector's background thread processing events from interface
    """
    def __init__(self, connector):
        super().__init__()
        self.__connector = connector
        self.__canceled = False
        self.daemon = True

    def cancel(self):
        """Cancel IO thread"""
        self.__canceled = True

    def run(self):
        """Main task.
        """
        while not self.__canceled:
            try:
                # Retrieve pending event
                with self.__connector.get_event(timeout=1.0) as evt:
                    # If event is a disconnection event, notify connector
                    if isinstance(evt, Disconnected):
                        self.__connector.on_disconnection()
                    # If event is a notification of a message
                    elif isinstance(evt, MessageReceived):
                        # Let connector process this message
                        self.__connector.dispatch_message(evt.message)
            except Empty:
                pass

class Event:
    """Generic connector event class.
    """

class Connector(WhadDeviceConnector):
    """New implementation that differs a bit from the previous one, using
    message queues.
    """

    def __init__(self, iface: Interface):
        """Initialization
        """
        super().__init__(iface)

        # Queue holding events coming from our interface
        self.__events = Queue()

        # Create a background thread for message processing
        self.__io_thread = ConnIoThread(self)
        self.__io_thread.start()

        # Event listeners
        self.__listeners = []

    def send_event(self, event):
        """Send an event into the connector event queue.
        """
        self.__events.put(event)

    def add_listener(self, listener: Callable[..., None],event_cls: Union[List[Event],
                                                                    Event] = None):
        """Add a connector event listener with optional event filter.

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

    def notify(self, event: Event):
        """Notify listeners of a specific event.
        """
        for listener, events in self.__listeners:
            if events is None:
                listener(event)
            elif event.__class__ in events:
                listener(event)

    @contextlib.contextmanager
    def get_event(self, timeout: float = None) -> Generator[IfaceEvt, None, None]:
        """Retrieve event from connector's event queue.
        """
        try:
            yield self.__events.get(timeout=timeout)
        except Empty as err:
            raise err
        else:
            self.__events.task_done()

    def dispatch_message(self, message):
        """Dispatch message to the connector's handlers.

        This method may trigger specific message processing in inherited
        connector's classes as well as attached protocol stacks. Since it
        is only called by the connector's I/O thread, that's pretty safe.
        """
        # Forward message to our any message handler
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
                        # Convert message into packet
                        packet = message.to_packet()
                        if packet is not None:
                            self.monitor_packet_rx(packet)
                            if self.is_synchronous():
                                self.add_pending_packet(message)
                            else:
                                self.on_packet(packet)
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
