"""
WHAD default device connector module.

This module provides a default connector class `WhadDeviceConnector` that
implements all the basic features of a device connector.
"""
import logging
from queue import Queue, Empty
from threading import Lock

from whad.helpers import message_filter
from whad.hub import ProtocolHub
from whad.hub.generic.cmdresult import CommandResult, Success
from whad.exceptions import WhadDeviceError, WhadDeviceDisconnected, \
    RequiredImplementation

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