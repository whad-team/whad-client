Introduction
============

What is WHAD ?
--------------

A lot of wireless hacking tools have been published by the cybersecurity community
based on various hardware platforms and custom communication protocols specifically
designed to work with associated software. This leads to hackers buying a lot of
different hardware devices to only use them with their associated tools, while
most hardware devices could be used with multiple tools if a compatible firmware
were available. Why not make all these theoritically compatible devices able to
communicate with a computer in a generic way, thus allowing generic tools to use
them ?

WHAD stands for *Wireless HAcking Devices* and is an attempt to unify the way
wireless hacking hardware communicates with computers in order to make them
compatible with generic tools provided in this framework. 


Main concepts behind WHAD
-------------------------

The main idea behind WHAD is quite simple: let the hardware handle hardware tasks
and keep the logic on the computer. WHAD provides a generic protocol to be used
by devices in a way it can discover the capabilities of any device and determine
which wireless protocol is supported and what can be done with it (sniffing,
initiating connections, hijacking, etc.).

Since each WHAD-compatible device does not implement any high-level logic, this
can be done in a generic way by the WHAD framework and therefore any operation
or attack implemented in WHAD may be performed by any compatible (and capable)
device.

Of course, WHAD provides many host-based wireless protocol stacks such as
Bluetooth Low Energy and ZigBee that may be tuned to implement some attacks or
to fuzz a specific protocol.

WHAD-compatible devices
-----------------------

We do also provide a set of WHAD-enable firmwares for various hardware platforms:

* ESP32-WROOM-32 (NodeMCU)
* nRF52840 dongle

Some other devices were made compatible with WHAD through an adaptation layer (no firmware update required):

* Ubertooth One
* Bluetooth HCI dongles


Supported wireless protocols
----------------------------

WHAD supports the following protocols:

* Bluetooth Low Energy (version 4.x, features from version 5.x are not yet implemented)
* ZigBee
* ANT
* ANT+
* Mosart



