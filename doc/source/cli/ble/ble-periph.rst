wble-periph: Bluetooth Low Energy GATT server
=============================================

``wble-periph`` provides a GATT server with customizable services and characteristics
as well as some advertising data records. This tool must be used with a device
supporting the *Bluetooth Low Energy* domain.

.. contents:: Table of Contents
    :local:
    :depth: 1


Usage
-----

.. code-block:: text

    wble-periph [OPTIONS] ([COMMAND] ([COMMAND ARGS]))

``wble-periph`` accepts one or more options, and requires a valid command as its
first parameter. This command may or may not accepts arguments.

Command-line options
--------------------

**wble-periph** supports the following options:

* ``--interface`` (``-i``): specifies the WHAD interface to use
* ``--bdaddr`` (``-b``): specifies a Bluetooth Device address to use for the GATT server in the form *XX:XX:XX:XX:XX:XX*
* ``--file`` (``-f``): provides a script to execute
* ``--no-color``: disables colors in output
* ``--profile`` (``-p``): specifies a device profile file (JSON) that will be used to populate GATT services, characteristics and advertisement info

.. include:: ../generic/debug-options.rst

Quick tutorial
--------------

Configuring a peripheral
~~~~~~~~~~~~~~~~~~~~~~~~

`wble-periph` exposes an interactive shell that provides all the required features
to create a GATT peripheral with services and characteristics. It must be started
with the specific interface you want to use (in this case *hci0*):

.. code-block:: text

    $ wble-periph -i hci0
    wble-periph>

First, we add a generic service (*Generic Access*):

.. code-block:: text

    wble-periph> service add 1800
    Service 1800 successfully added.
    wble-periph|service(1800)>

Once this service added, it is automatically selected as shown in the prompt. We can
add a characteristic:

.. code-block:: text

    wble-periph|service(1800)> char add 2a00 read notify
    Successfully added characteristic 2A00
    wble-periph|service(1800)>

Once done, we deselect the currently selected service using the `back` command:

.. code-block:: text

    wble-periph|service(1800)> back
    wble-periph>

And we can check our created GATT profile with the `service` command, as shown below:

.. code-block:: text

    wble-periph> service
    Service 1800 (Generic Access) (handles from 2 to 5):
    └─ Characteristic 2A00 (Device Name)
    └─ handle:3, value handle: 4, props: read,notify
    └─ Descriptor 2902 (handle: 5)
    wble-periph>

Eventually, we set the complete device name for our peripheral, and write the same
name in the 2A00 characteristic (which is supposed to contain the device name):

.. code-block:: text

    wble-periph> name "WHAD DemoDevice"
    Device name set to "WHAD DemoDevice"
    wble-periph> write 2a00 "WHAD DemoDevice"
    wble-periph> read 2a00
    00000000: 57 48 41 44 20 44 65 6D  6F 44 65 76 69 63 65     WHAD DemoDevice
    wble-periph>



Importing an existing profile
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Instead of creating services and characteristics by hand, we can import a dumped
json profile that will populate all the services and characteristics by using the
`-p` option:

.. code-block:: text

    $ wble-periph -i hci0 -p mydevice.json

This will launch an interactive shell with the peripheral GATT profile populated with
the specified JSON file. We can check the provided profile has been successfully loaded:

.. code-block:: text

    wble-periph> service
    Service 1800 (Generic Access) (handles from 1 to 9):
    ├─ Characteristic 2A00 (Device Name)
    │ └─ handle:2, value handle: 3, props: read
    ├─ Characteristic 2A01 (Appearance)
    │ └─ handle:4, value handle: 5, props: read
    ├─ Characteristic 2A04 (Peripheral Preferred Connection Parameters)
    │ └─ handle:6, value handle: 7, props: read
    └─ Characteristic 2AA6 (Central Address Resolution)
    └─ handle:8, value handle: 9, props: read
    Service 1801 (Generic Attribute) (handles from 10 to 13):
    └─ Characteristic 2A05 (Service Changed)
    └─ handle:11, value handle: 12, props: indicate
    └─ Descriptor 2902 (handle: 13)
    Service adabfb00-6e7d-4601-bda2-bffaa68956ba (handles from 14 to 27):
    ├─ Characteristic adabfb04-6e7d-4601-bda2-bffaa68956ba
    │ └─ handle:15, value handle: 16, props: read
    ├─ Characteristic adabfb02-6e7d-4601-bda2-bffaa68956ba
    │ └─ handle:17, value handle: 18, props: read
    ├─ Characteristic adabfb03-6e7d-4601-bda2-bffaa68956ba
    │ └─ handle:19, value handle: 20, props: read,notify
    │ └─ Descriptor 2902 (handle: 21)
    ├─ Characteristic adabfb01-6e7d-4601-bda2-bffaa68956ba
    │ └─ handle:22, value handle: 23, props: notify
    │ └─ Descriptor 2902 (handle: 24)
    └─ Characteristic adabfb05-6e7d-4601-bda2-bffaa68956ba
    └─ handle:25, value handle: 26, props: indicate
    └─ Descriptor 2902 (handle: 27)
    Service 558dfa00-4fa8-4105-9f02-4eaa93e62980 (handles from 28 to 31):
    └─ Characteristic 558dfa01-4fa8-4105-9f02-4eaa93e62980
    └─ handle:29, value handle: 30, props: read,notify
    └─ Descriptor 2902 (handle: 31)
    Service 180A (Device Information) (handles from 32 to 50):
    ├─ Characteristic 2A29 (Manufacturer Name String)
    │ └─ handle:33, value handle: 34, props: read
    ├─ Characteristic 2A24 (Model Number String)
    │ └─ handle:35, value handle: 36, props: read
    ├─ Characteristic 2A25 (Serial Number String)
    │ └─ handle:37, value handle: 38, props: read
    ├─ Characteristic 2A27 (Hardware Revision String)
    │ └─ handle:39, value handle: 40, props: read
    ├─ Characteristic 2A26 (Firmware Revision String)
    │ └─ handle:41, value handle: 42, props: read
    ├─ Characteristic 2A28 (Software Revision String)
    │ └─ handle:43, value handle: 44, props: read
    ├─ Characteristic 2A23 (System ID)
    │ └─ handle:45, value handle: 46, props: read
    ├─ Characteristic 2A2A (IEEE 11073­20601 Regulatory Certification Data List)
    │ └─ handle:47, value handle: 48, props: read
    └─ Characteristic 2A50 (PnP ID)
    └─ handle:49, value handle: 50, props: read


Starting our peripheral and interacting with characteristics
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once done, we can start our peripheral:

.. code-block:: text

    wble-periph> start
    wble-periph[running]>
    
We get a notification in the interactive console when a device connects to our
peripheral:

.. code-block:: text

    New connection handle:68
    wble-periph[running]>

And we also get some notification when a device is read, written or subscribed to:

.. code-block:: text

    Reading characteristic 2A00 of service 1800
    00000000: 57 48 41 44 20 54 65 73  74 44 65 76 69 63 65     WHAD TestDevice
    Subscribed to characteristic 2A00 of service 1800
    Unsubscribed to characteristic 2A00 of service 1800
    Disconnection handle:68

While a peripheral is running, we can write and read the values of characteristics:

.. code-block:: text

    wble-periph[running]>write 2a00 notified
    wble-periph[running]>read 2a00
    00000000: 6E 6F 74 69 66 69 65 64                           notified

If we write to a characteristic a device has subscribed to for notification/indication,
it will send a notification/indication to the connected device.

Changing the connection MTU
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The `mtu` command can be used when a connection is established to change the
*maximum transmission unit* or *MTU*:

.. code-block:: text

    wble-periph[running]> mtu 200
    Connection MTU set to 200.

.. important::

    MTU value must be equal to or greater than 23.

Stopping our peripheral
~~~~~~~~~~~~~~~~~~~~~~~

The `stop` command will stop our peripheral and disconnect any connected device:

.. code-block:: text

    wble-periph[running]> stop
    wble-periph>


Supported commands
------------------

help
~~~~

.. code-block:: text

    $ wble-periph help [command]

The ``help`` command provides useful help about any command implemented in ``wble-periph``.

interactive
~~~~~~~~~~~

.. code-block:: text

    $ wble-periph -i <interface> interactive

The ``interactive`` command provides an interactive shell allowing the user to
scan, connect and access a Bluetooth Low Energy device in an interactive way.

A WHAD interface name must be be provided through the ``--interface`` option for
this interactive shell to work properly. It will complain if you forget to provide
one. 

.. code-block:: text

    $ wble-periph -i hci0 interactive
    wble-periph>

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

    wble-periph> service add 1800
    Service 1800 successfully added.

The generic syntax for adding a service is the following:

.. code-block:: text

    service  add <UUID>

With `UUID` the 16-bit or 128-bit UUID of the service to create. You cannot create
two services with the same UUID. When the service has successfully been added,
the shell automatically selects it in order to declare the corresponding characteristics
with the `char <char_command>` command. The prompt displays the selected service:

.. code-block:: text

    wble-periph|service(1800)>


To remove a service, use the `remove` action with an existing UUID:

.. code-block:: text

    service remove <UUID>

Adding or removing services is forbidden when a service has been selected. See
the `back <back_command>` to exit service edit mode. 

When no action is given, this command lists the declared services and characteristics,
with all their associated handles and descriptors:

.. code-block:: text

    wble-periph> service
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

    wble-periph|service(1800)> char add 0x2A00 read notify 

The following rights are supported:

* `read`: allow read access to the characteristic value (default)
* `write`: allow write access to the characteristic value
* `notify`: allow notifications (use a Client Characteristic Configuration Descriptor (CCCD))
* `indicate`: allow indications (use a Client Characteristic Configuration Descriptor (CCCD))

The `remove` action can be used to remove an existing characteristic from the currently
selected service:

.. code-block:: text

    wble-periph|service(1800)> char remove 0x2A00

write
~~~~~

.. code-block:: text

    write [UUID | handle] [VALUE]

This command writes the specified *VALUE* into a characteristic. *VALUE* can be
some hex data, if prefixed with the **hex** keyword, or just a text string. The
following are valid commands setting the value of a characteristic:

.. code-block:: text

    wble-periph|service(1800)> write 0x2A00 "DeviceName"
    wble-periph|service(1800)> write 0x2A00 hex 41 42 43


read
~~~~

.. code-block:: text

    read [UUID | handle]

This commands reads the value of a characteristic designed by its handle or UUID:

.. code-block:: text

    wble-periph|service(1800)> read 0x2A00
    00000000: 54 65 73 74 44 65 76 69  63 65                    TestDevice


name
~~~~

.. code-block:: text

    name [NAME]

This command configures the complete name that will be advertised in the advertising data records.

Example:

.. code-block:: text

    wble-periph> name TestDevice

shortname
~~~~~~~~~

.. code-block:: text

    shortname [NAME]

This command configures the short name that will be advertised in the advertising data records.

**Example:**

.. code-block:: text

    wble-periph> shortname TestDevice

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

    wble-periph> manuf 0x0001 4142434445


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

mtu
~~~

.. code-block:: text

    mtu [MTU]

This command starts an ATT MTU exchange procedure: the GATT server will send an1 MTU exchange request
with the specified MTU value to the connected Central device and await an MTU exchange response.
The connection MTU is automatically updated when a response is received, or discarded if the Central
device declined the MTU update.

.. important::

    The MTU value must be >= 23, as stated in the Bluetooth specification.