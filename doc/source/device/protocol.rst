WHAD communication protocol
===========================

WHAD communication protocol has been designed with the following ideas in mind:

- Genericity: the protocol is the same for all supported devices and allows the host to discover what a device is capable of and adapt its features based on this
- Extensibility: the protocol must allow new wireless protocols or modulation to be added easily with backward compatibility
- Efficiency: exchanges must be as compact as possible to provide a good throughput
- Stability: backward compatibility is key and older versions of this protocol must be supported

Based on this, we decided to go with *Protocol Buffers* as it is a widely known compact protocol
to create messages that can be exchanged between devices and computers, supported by a wide variety
of programming languages and systems.

Main concepts behind our protocol
---------------------------------

WHAD protocol has been designed to allow hardware to handle hardware stuff and time-critical operations, letting
the host software handling all the complex procedures and computations whenever it is possible. With this offloading
of complex tasks, a compatible firmware code is reduced to its minimum and just needs to support a set of basic and
sometimes extended commands to support one of more features available on the host.

This specificity allows faster compatible firmware development and let any compatible WHAD device support any tool
that will be developed in the future.

Protocol definition
-------------------

WHAD exposes `a dedicated repository <https://github.com/whad-team/whad-protocol>`_ describing all the messages our protocol uses, and including some
compilation scripts that may help generating C and Python files that are used in both our various
compatible firmwares repository and WHAD's main client repository.

Protocol messages are split in three main categories:

- Generic messages: these messages are considered generic and are used by *domains* and our *discovery* protocol, see below
- Discovery messages: these messages are used by our *discovery* protocol that is not supposed to change in the future for stability (unless a critical issue is discovered of course)
- Domain-specific messages: these messages are specific to a *domain* and could evolve in the future

Generic messages
^^^^^^^^^^^^^^^^

This type of messages mostly include:

- basic command result and error messages, used all the time to report to the host the failure or success of a command
- debug and verbose messages, used by developers during firmware development to report more information to the host

Discovery protocol
^^^^^^^^^^^^^^^^^^

WHAD discovery protocol is designed to allow any compatible host to discovery any device capabilities. So any compatible
device MUST support at least this discovery protocol ! This protocol allows the host to retrieve some critical information such as:

- firmware source repository or website
- firmware version string
- author name
- maximum WHAD protocol version supported, used to adapt further communications
- supported *domains* and commands for each supported *domain*

This discovery protocol is used at the beginning of the communication between a compatible device and its host in order
for the host to determine what features are compatible with this device and how to correctly communicate with it.

Domain-specific protocols
^^^^^^^^^^^^^^^^^^^^^^^^^

The WHAD protocol includes a set of supported domains that may change in the future, and for each domain provides a set
of commands and notification messages that can be exchanged between a host computer and a compatible device to provide
all the possible features for the given domain.

Since this protocol is extensible, future domains will be included as specific messages categories and will not cause
any issue if used when a host that does not support the latest version of this protocol. Any newly added domain will
just not be available to this host until the client software gets updated.

