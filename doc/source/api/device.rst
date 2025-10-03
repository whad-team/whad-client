
Devices and connectors
======================

In WHAD, *devices* and *connectors* are two different components that are used
together to allow users and applications to perform various actions on wireless
networks, using compatible hardware.

A *device* defines a compatible hardware device that is plugged to the host
computer running WHAD, could it be an internal device present on a motherboard
or an external device connected through a USB port. Such a device is represented
in WHAD by a class that derives from the :py:class:`~whad.device.device.Device` class
acting as an interface between the framework and the real hardware used to communicate
over the air with other networks and peripherals.

WHAD support the following hardware devices:
- Internal bluetooth adapters (installed on motherboard), supporting at least Bluetooth version >= 4.0
- USB Bluetooth dongles, supporting at least Bluetooth version >= 4.0
- [Great Scott Gadgets' Ubertooth One](https://greatscottgadgets.com/ubertoothone/)
- [Great Scott Gadgets' Yard Stick One](https://greatscottgadgets.com/yardstickone/)
- [River Loop Security's ApiMote](http://apimote.com/)
- [Nordic nRF52840 USB dongle](https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle)
- [Maker Diary's nRF52840 MDK USB dongle](https://makerdiary.com/products/nrf52840-mdk-usb-dongle)

Some devices are supported natively (running a custom firmware implementing our WHAD protocol) while others
are supported through a dedicated adaptation layer in a dedicated class inheriting from
:py:class:`~whad.device.device.VirtualDevice`. 

Device classes are strongly tied to a specific hardware (and firmware, if required)
and basically take WHAD messages in input and output WHAD messages too. WHAD protocol
includes a discovery feature allowing each device to tell the host computer what *domains*
it support (think of *domains* as *wireless protocols*) and its *capabilities* for
each of them, as well as the set of *commands* supported for each *domain*.

*Connectors* on the other hand are not tied to any specific hardware but rather to
a specific *domain* and a set of *capabilities*. A *connector* acts as a specialized
role applied to a compatible hardware device, and exposes a set of actions that can
be used by any application, no matter the hardware since it at least supports the
required *domain* and *capabilities*. This way, any high-level interaction implemented
in a *connector* can be used with any hardware that provides the required *capabilities*
for a given *domain*, making it easier to create custom firmwares for new hardware
without having to care about how some wireless attack or procedure is implemented.

.. automodule:: whad.device
