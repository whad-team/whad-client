Bluetooth Low Energy GATT server
================================

``ble-periph`` provides a GATT server with customizable services and characteristics
as well as some advertising data records. This tool must be used with a device
supporting the *Bluetooth Low Energy* domain.

.. contents:: Table of Contents
    :local:
    :depth: 1


Usage
-----

.. code-block:: text

    ble-periph [OPTIONS] ([COMMAND] ([COMMAND ARGS]))

``ble-periph`` accepts one or more options, and requires a valid command as its
first parameter. This command may or may not accepts arguments.

Command-line options
--------------------

**ble-periph** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use
* ``--bdaddr`` (``-b``): specifies a Bluetooth Device address to use for the GATT server in the form *XX:XX:XX:XX:XX:XX*
* ``--file`` (``-f``): provides a script to execute
* ``--no-color``: disables colors in output

Supported commands
------------------

help
~~~~

.. code-block:: text

    $ ble-central help [command]

The ``help`` command provides useful help about any command implemented in ``ble-central``.

interactive
~~~~~~~~~~~

.. code-block:: text

    $ ble-central -i <interface> interactive

The ``interactive`` command provides an interactive shell allowing the user to
scan, connect and access a Bluetooth Low Energy device in an interactive way.

A WHAD interface name must be be provided through the ``--interface`` option for
this interactive shell to work properly. It will complain if you forget to provide
one. 

.. code-block:: text

    $ ble-periph -i hci0 interactive
    ble-periph>

More information about this interactive shell in the :ref:`dedicated section <periph-interactive-shell>`.


Interactive shell
-----------------

.. _periph-interactive-shell:

The interactive shell offers the possibility to dynamically create any BLE peripheral
(GATT server), with an helpful interface that provides autocompletion. 

service
~~~~~~~

.. code-block:: text

    service [add|remove] [UUID]

This command can add, edit and remove services from the current GATT server. The
`add` action creates a new service with the provided UUID, as shown below:

.. code-block:: text

    ble-periph> service add 1800
    Service 1800 successfully added.

The generic syntax for adding a service is the following:

.. code-block:: text

    service  add <UUID>

With `UUID` the 16-bit or 128-bit UUID of the service to create. You cannot create
two services with the same UUID. When the service has successfully been added,
the shell automatically selects it in order to declare the corresponding characteristics
with the `char <char_command>` command. The prompt displays the selected service:

.. code-block:: text

    ble-periph|service(1800)>


To remove a service, use the `remove` action with an existing UUID:

.. code-block:: text

    service remove <UUID>

Adding or removing services is forbidden when a service has been selected. See
the `back <back_command>` to exit service edit mode. 

When no action is given, this command lists the declared services and characteristics,
with all their associated handles and descriptors:

.. code-block:: text

    ble-periph> service
    Service 1800 (Generic Access) (handles from 1 to 5):
    ├─ Characteristic 2A00 (Device Name)
    │ └─ handle:2, value handle: 3, props: read
    └─ Characteristic 2A01 (Appearance)
    └─ handle:4, value handle: 5, props: read


char
~~~~

.. _char_command:

.. code-block:: text

    char [add|remove] [UUID] [RIGHTS]

This command can add, edit and remove a characteristic from the selected service.
The `add` action creates a new characteristic with the provided UUID and rights,
as shown below:

.. code-block:: text

    ble-periph|service(1800)> char add 0x2A00 read notify 

The following rights are supported:

* `read`: allow read access to the characteristic value (default)
* `write`: allow write access to the characteristic value
* `notify`: allow notifications (use a Client Characteristic Configuration Descriptor (CCCD))
* `indicate`: allow indications (use a Client Characteristic Configuration Descriptor (CCCD))

The `remove` action can be used to remove an existing characteristic from the currently
selected service:

.. code-block:: text

    ble-periph|service(1800)> char remove 0x2A00

write
~~~~~

.. code-block:: text

    write [UUID | handle] [VALUE]

This command writes the specified *VALUE* into a characteristic. *VALUE* can be
some hex data, if prefixed with the **hex** keyword, or just a text string. The
following are valid commands setting the value of a characteristic:

.. code-block:: text

    ble-periph|service(1800)> write 0x2A00 "DeviceName"
    ble-periph|service(1800)> write 0x2A00 hex 41 42 43


read
~~~~

.. code-block:: text

    read [UUID | handle]

This commands reads the value of a characteristic designed by its handle or UUID:

.. code-block:: text

    ble-periph|service(1800)> read 0x2A00
    00000000: 54 65 73 74 44 65 76 69  63 65                    TestDevice


name
~~~~

.. code-block:: text

    name [NAME]

This command configures the complete name that will be advertised in the advertising data records.

Example:

.. code-block:: text

    ble-periph> name TestDevice

shortname
~~~~~~~~~

.. code-block:: text

    shortname [NAME]

This command configures the short name that will be advertised in the advertising data records.

**Example:**

.. code-block:: text

    ble-periph> shortname TestDevice

manuf
~~~~~

.. code-block:: text

    manuf [COMPANY_ID] [HEX DATA]

This command configures a manufacturer data record that will be advertised, specifying the company
ID and manufacturer-specific data to be included in this record.

*COMPANY_ID* could be a standard company name or a 16-bit ID defining a company (see *Bluetooth 
Assigned Numbers* document to find the complete list of company IDs).

*HEX DATA* is any valid hex data bytes, without spaces.

**Example:**

.. code-block:: text

    ble-periph> manuf 0x0001 4142434445


start
~~~~~

.. code-block:: text

    start

This command starts advertising a peripheral and will allow connections. Once a device connected
to the emulated peripheral, it will expose the configured services and characteristics.

stop
~~~~

.. code-block:: text

    stop

This command stops the currently running peripheral. It will disconnect any connected device.


Quick tutorial
--------------