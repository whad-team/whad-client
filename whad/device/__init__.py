"""
Devices
-------

WHAD provides various classes to interact with WHAD-enabled hardware:

- :py:class:`whad.device.device.Device`
- :py:class:`whad.device.device.VirtualDevice`

Class :class:`whad.device.device.Device` is the default class that allows WHAD devices
enumeration and access. It is the main class to use to open any device, through
its :py:meth:`whad.device.Device.create` method as shown below:

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
    :py:class:`whad.device.device.Device` class, and is meant to be deprecated in the future.
    This old class has been renamed to ``Device`` for clarity, and the same happened
    with the old default connector class :py:class:`whad.device.connector.WhadConnector`
    that has been renamed to :py:class:`whad.device.connector.Connector`.

    These old classes will be marked as *deprecated* in a future release, with a
    specific EOL date announced. A warning message will be issued in case one of
    these classes is used in a script or a tool to give time to users to migrate
    to the new ones (renaming classes is enough to switch to the new implementation,
    APIs stay the same).


.. autoclass:: whad.device.device.Device
    :members:

.. autoclass:: whad.device.device.VirtualDevice
    :members:


Connectors
----------

*Connectors* shall ensure the device they are linked to does support the
target domain and a mimimal set of commands, and can tailor its behavior
depending on the capabilities of the hardware. If a *connector* is linked
to a device that either does not support the *domain* this *connector* is
supposed to operate or lacks specific *commands*, a
:py::class:`whad.exceptions.UnsupportedDomain` exception or a
:py:class:`whad.exceptions.UnsupportedCapability` may be raised.

WHAD provides a default connector class, :py:class:`whad.device.connector.Connector`,
that implements a set of features out-of-the-box:

- Packet and message sniffing and processing
- Event notification mechanism
- Synchronous mode

Sniffing packet and messages could be useful to implement packet sniffers or
intercept some specific events like disconnection of the linked hardware device.
Most of the time this feature is used to sniff packets related to a target domain.
The :py:meth:`whad.device.connector.Connector.sniff` method is specifically
tailored for this use. When not sniffing, packets received from the hardware device
are forwarded to the connector's packet processing methods than can be overriden by
inheriting classes.

By default, the default connector class provides methods to add and remove custom
event listeners (:py:meth:`whad.device.connector.Connector.add_listener` and
:py:meth:`whad.device.connector.Connector.remove_listener`), and an additional
method to send an event to the registered listeners (:py:meth:`whad.device.connector.Connector.notify`).

Last but not least, the provided *synchronous mode* will disable packet forwarding
and save all received packets in a reception queue, waiting for the application to
retrieve and process them. Service messages will still be processed by the *connector*,
in order to handle any device disconnection or other unexpected event that may occur.
When this *synchronous mode* is disabled, every unprocessed packet stored in the
reception queue are automatically forwarded to the connector's packet processing
methods, and will be then dispatched to the corresponding handlers.

.. autoclass:: whad.device.connector.Connector
    :members:

    .. automethod:: __init__

.. autoclass:: whad.device.connector.LockedConnector
    :members:

    .. automethod:: __init__

Deprecated classes
------------------

In early versions of WHAD, device and connector base classes had different names
that were too long and badly chosen. We took the decision to rename them while
keeping the old classes as aliases of the new ones. This way, old code and documentation
and even tools keep working as expected, until we decide to definitely deprecate
these old classes. For now, they are still defined and available, but we will mark
them as deprecated starting from version 1.3.

A warning will be displayed each time such a class is used, inciting users and
maintainers to update their code to use the new classes, which are strictly
compatible as they expose the same methods and properties. This warning will
include a deadline after which these classes will be definitely removed.

.. autoclass:: whad.device.device.WhadDevice
    :show-inheritance:

.. autoclass:: whad.device.device.WhadVirtualDevice
    :show-inheritance:

.. autoclass:: whad.device.connector.WhadDeviceConnector
    :show-inheritance:
"""

# Load interface base classes
from .device import Device, VirtualDevice, DeviceEvt, Disconnected, MessageReceived, \
    WhadDevice, WhadVirtualDevice
from .connector import Connector, Event, LockedConnector, WhadDeviceConnector
from .bridge import Bridge

# Base device classes
from .uart import Uart
from .tcp import TcpSocket
from .unix import UnixSocket

__all__ = [
    # Base classes
    "Device",
    "VirtualDevice",
    "Connector",
    "WhadDeviceConnector",
    "Bridge",
    "DeviceEvt",
    "Disconnected",
    "MessageReceived",
    "Event",

    # Kept for compatibility
    "WhadDevice",
    "WhadVirtualDevice",
    "WhadDeviceConnector",
    "LockedConnector",

    # Base devices
    "TcpSocket",
    "Uart",
    "UnixSocket",
]
