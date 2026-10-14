BLE Proxy classes
=================

.. contents::
   :local:

.. py:currentmodule:: whad.ble.tools.proxy

WHAD provides two Bluetooth Low Energy proxy classes that sit between a real
peripheral and a remote central device, using two BLE-capable WHAD interfaces.
A proxy connects to the target peripheral as a Central, then advertises a
mirror device that a remote Central can connect to, and forwards traffic
between the two ends. Two flavors are available:

* :class:`LinkLayerProxy` operates at the link layer and forwards Control and
  Data PDUs in both directions, giving the caller a chance to inspect or
  rewrite each PDU before it is delivered.
* :class:`GattProxy` operates at the GATT layer, imports the target's GATT
  database, and forwards read, write, subscribe and notification or indication
  operations. The caller can hook each operation to inspect or override
  values.

Both classes are designed to be subclassed. Override the callbacks documented
below to implement custom behavior such as logging, filtering or value
rewriting.

Link-layer proxy
----------------

The :class:`LinkLayerProxy` connector relays raw BLE link-layer PDUs between
a Central role (connected to the target device) and a Peripheral role
(exposed to the remote Central). It does not parse the GATT layer, so it
preserves the original PDU framing as observed on air.

Creating a link-layer proxy
~~~~~~~~~~~~~~~~~~~~~~~~~~~

A :class:`LinkLayerProxy` instance needs two BLE-capable WHAD interfaces and
the Bluetooth Device Address of the target peripheral:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble.tools.proxy import LinkLayerProxy

    proxy_iface = WhadDevice.create("hci0")
    target_iface = WhadDevice.create("hci1")

    proxy = LinkLayerProxy(
        proxy=proxy_iface,
        target=target_iface,
        bd_address="00:11:22:33:44:55",
        random=False,
    )

    proxy.start()

The ``proxy`` interface is used to advertise the mirror device, while the
``target`` interface acts as a Central and connects to the real peripheral
identified by ``bd_address``. Setting ``random=True`` selects a random
address type for the target peripheral. Custom advertising and scan response
records can be supplied through the ``adv_data`` and ``scan_data``
parameters (see :class:`~whad.ble.profile.advdata.AdvDataFieldList`).

If the underlying Central connection cannot be established (wrong address
type, peer unreachable), the peripheral half is never created. The
:meth:`LinkLayerProxy.on_central_event` callback then receives a
:class:`~whad.ble.connector.central.CentralDisconnected` event without a
live peripheral attached and the implementation handles this case
defensively (see :ref:`ble-proxy-disconnect-handling`).

Hooking link-layer traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~

Subclass :class:`LinkLayerProxy` and override :meth:`~LinkLayerProxy.on_ctl_pdu`
or :meth:`~LinkLayerProxy.on_data_pdu` to inspect or rewrite forwarded PDUs.
Returning the original PDU forwards it as-is, returning a modified PDU
forwards the modified copy, and returning ``None`` drops the PDU:

.. code-block:: python

    from whad.ble.tools.proxy import LinkLayerProxy

    class LoggingLinkLayerProxy(LinkLayerProxy):
        def on_data_pdu(self, pdu, direction):
            print(f"data pdu ({direction}): {bytes(pdu).hex()}")
            return pdu

        def on_ctl_pdu(self, pdu, direction):
            print(f"ctl pdu ({direction}): {bytes(pdu).hex()}")
            return pdu

The :meth:`~LinkLayerProxy.on_connect` and
:meth:`~LinkLayerProxy.on_disconnect` callbacks fire when a remote Central
connects to or disconnects from the advertised mirror device.

GATT proxy
----------

The :class:`GattProxy` connector operates one layer higher. On startup it
connects to the target peripheral as a Central, performs a GATT service and
characteristic discovery (or imports a JSON profile), and then exposes a
mirror peripheral with the same profile. GATT operations from the remote
Central are translated into the matching operation against the target
device, and the caller can hook each operation to observe or override the
exchanged values.

Creating a GATT proxy
~~~~~~~~~~~~~~~~~~~~~

The constructor takes the same two interfaces plus the target Bluetooth
Device Address. An existing JSON profile can be supplied through the
``profile`` parameter to skip the discovery step:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.ble.tools.proxy import GattProxy

    proxy_iface = WhadDevice.create("hci0")
    target_iface = WhadDevice.create("hci1")

    proxy = GattProxy(
        proxy=proxy_iface,
        target=target_iface,
        bd_address="00:11:22:33:44:55",
        random=False,
    )

    proxy.start()

Custom advertising and scan response data are accepted through the
``adv_data`` and ``scan_data`` parameters. Once :meth:`GattProxy.start`
returns, the mirror device is advertising and ready to accept a remote
Central connection.

Hooking GATT operations
~~~~~~~~~~~~~~~~~~~~~~~

Subclass :class:`GattProxy` and override any of the GATT callbacks to react
to operations triggered by the remote Central:

.. code-block:: python

    from whad.ble.tools.proxy import GattProxy
    from whad.ble.exceptions import HookReturnValue

    class LoggingGattProxy(GattProxy):
        def on_characteristic_read(self, service, characteristic,
                                   value, offset=0, length=0):
            print(f"read {characteristic.uuid}: {value!r}")

        def on_characteristic_write(self, service, characteristic,
                                    offset=0, value=b"",
                                    without_response=False):
            print(f"write {characteristic.uuid}: {value!r}")
            # Rewrite the value forwarded to the target device:
            raise HookReturnValue(b"patched")

        def on_notification(self, service, characteristic, value):
            print(f"notify {characteristic.uuid}: {value!r}")

Raising :class:`~whad.ble.exceptions.HookReturnValue` from a write or
subscription callback replaces the forwarded value. Raising
:class:`~whad.ble.exceptions.HookDontForward` from a notification or
indication callback drops the event so the remote Central does not see it.
The other hooking exceptions documented in :doc:`exceptions` are accepted as
well and translate into the matching GATT error toward the remote Central.

.. _ble-proxy-disconnect-handling:

Disconnection handling and the on_central_event callback
--------------------------------------------------------

Both proxy classes register :meth:`~LinkLayerProxy.on_central_event` and
:meth:`~GattProxy.on_central_event` as event handlers on the internal
Central connector, and use them to react to a
:class:`~whad.ble.connector.central.CentralDisconnected` event so the proxy
can rebuild a fresh connection to the target device.

The internal peripheral half is only created once the Central side has
successfully connected to the target. If the Central connection fails early
(for example, the peer is unreachable or the address type is wrong), the
peripheral attribute stays unset while the disconnect event still fires on
the Central event handler. The callbacks therefore guard the peripheral
access with a non-nil check, and log ``peripheral not connected`` for the
not-connected branch, before attempting to reconnect:

.. code-block:: python

    def on_central_event(self, event):
        if isinstance(event, CentralDisconnected):
            if self.__peripheral is not None \
                    and self.__peripheral.conn_handle is not None:
                self.__peripheral.disconnect(self.__peripheral.conn_handle)
                # ... tear down peripheral and listener
            else:
                logger.debug("[LinkLayerProxy] peripheral not connected")
            # Try to reconnect to the target device
            self.__central.stop()
            self.start()

Subclasses that override :meth:`~LinkLayerProxy.on_central_event` or
:meth:`~GattProxy.on_central_event` should preserve this nil-guard
invariant: the peripheral attribute may legitimately be ``None`` at the
moment the disconnect event is delivered, and dereferencing it would raise
``AttributeError`` inside the connector's background event thread.

PCAP and Wireshark monitors
---------------------------

Both proxy classes expose helpers that attach a PCAP writer or a live
Wireshark monitor to the internal Central, so the traffic captured between
the proxy and the target device can be saved or inspected:

.. code-block:: python

    pcap = proxy.get_pcap_monitor("capture.pcap")
    pcap.start()

    ws = proxy.get_wireshark_monitor()
    ws.start()

See :class:`~whad.common.monitors.PcapWriterMonitor` and
:class:`~whad.common.monitors.WiresharkMonitor` for the underlying monitor
classes.

Python API for BLE proxy classes
--------------------------------

Link-layer proxy connector
~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoclass:: whad.ble.tools.proxy.LinkLayerProxy
    :members:

GATT proxy connector
~~~~~~~~~~~~~~~~~~~~

.. autoclass:: whad.ble.tools.proxy.GattProxy
    :members:
