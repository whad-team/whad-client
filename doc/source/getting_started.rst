Getting started with WHAD
=========================

WHAD provides a Python framework to scan, sniff, emulate and connect to wireless
devices using various wireless protocols in a unified way, as well as command-line
tools to avoid scripting when possible. In WHAD, each wireless protocol is defined
as a specific **domain** that may be supported by one or more WHAD devices.

Get a compatible WHAD device
----------------------------

We put lot of efforts in implementing specific firmwares for existing wireless
hacking devices and/or development boards (see. :todo:`add here a link to the list of supported devices`),
but we also created a set of virtual devices to use some hardware devices without
having to reprogram them, including:

* any HCI adapter
* GreatScott's Ubertooth One

For clarity purposes, the following examples use a recent Bluetooth HCI adapter (version >= 4.x)
as it is widely spread and should be found in a lot of computers and laptops. They
should work straight out of the box if your computer has this type of device.
