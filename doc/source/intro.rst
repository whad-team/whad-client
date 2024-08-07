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
wireless hacking hardware devices communicate with computers in order to make them
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

Hardware interfaces
^^^^^^^^^^^^^^^^^^^

In WHAD, an *interface* is basically some piece of hardware that acts as a
transceiver: a device that is able to turn a series of bytes into air frames
and to receive air frames and turn them into a series of bytes, depending on a
modulation.

For some wireless protocols, this interface also handles time-critical operations
such as channel hopping or connection-specific procedures that cannot be handled
by the host.

Each hardware interface supports our discovery protocol: a protocol designed to
get as much information as possible from any interface including its capabilities,
its supported domains as well as the firmware it runs and where to find its source
code.

These interfaces exchange data with the host through our extensible WHAD
protocol.

Connectors
^^^^^^^^^^

WHAD also introduces the concept of *connectors*. A *connector* is an abstract
class that connects an interface to a specific domain and role. A *connector*
uses the interface communication channel to interact with it and exposes some
higher-level functions to the user, adding an abstraction layer. It also checks
that the specified device supports the required domain and capabilities, and
accepts all the commands required to achieve it task(s).

Connectors can inherit from other connectors as well, allowing specialization
and adding more abstraction level for the user thus making things simpler.




