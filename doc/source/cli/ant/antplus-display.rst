wantplus-display: ANT+ Display
===============================

``wantplus-display`` is a WHAD utility for discovering ANT+ devices, connecting
to supported ANT+ sensors, and displaying the data exposed by their profiles.
It provides an interactive shell to inspect profile attributes, monitor values,
request data pages, and optionally observe packets with Wireshark.

The tool requires a WHAD interface capable of communicating with ANT+ devices.

.. contents:: Table of Contents
   :local:
   :depth: 2


Usage
-----

Start the utility by specifying the WHAD interface to use:

.. code-block:: text

   $ wantplus-display -i <interface name>

For example:

.. code-block:: text

   $ wantplus-display -i uart0
   wantplus-display>

The application also defines ``--device-type`` (``-t``) to specify a target
ANT+ device type, and ``--file`` (``-f``) to specify a script file. See the
command-line help in your installation.

When the interactive shell is open, use ``help`` to list commands and
``help <command>`` to display help for a particular command.


Quick tutorial
--------------

This tutorial shows a typical workflow: scan for nearby ANT+ devices, connect
to one of the discovered devices, and inspect its profile.

Device discovery
^^^^^^^^^^^^^^^^

Use ``scan`` to discover nearby ANT+ devices. The command displays the signal
level (RSSI), device number, device type, transmission type, and detected
profile.

.. code-block:: text

   wantplus-display> scan
   RSSI Lvl   Dev. Num.     Dev. Type    Trans. Type      Profile
   [ -42 dBm] 1234         120           1                Heart Rate Monitor

The output above is illustrative. Actual values depend on the devices detected
nearby. Stop scanning with ``CTRL+C``.

The device types currently listed as supported by the utility are:

* ``119``: Weight Scale
* ``120``: Heart Rate Monitor
* ``121``: Combined Speed and Cadence
* ``122``: Bike Cadence Sensor
* ``123``: Bike Speed Sensor
* ``124``: Speed and Distance

Connecting to a sensor
^^^^^^^^^^^^^^^^^^^^^^^


Use the device number reported by ``scan`` to connect. The number can be
provided in decimal or hexadecimal notation.

.. code-block:: text

   wantplus-display> connect 1234
   Connected as Heart Rate Monitor to Dev. Num. 1234.

After a successful connection, the prompt indicates the active profile and
device number.

Inspecting a profile
^^^^^^^^^^^^^^^^^^^^^

The ``profile`` command lists the profile's attributes and its available data
pages. Attribute values and data-page fields depend on the connected sensor
profile.

.. code-block:: text

   wantplus-display|Heart Rate Monitor(120)| @1234> profile

To print one attribute, use ``get`` with the attribute name displayed by
``profile``:

.. code-block:: text

   wantplus-display|Heart Rate Monitor(120)| @1234> get <attribute_name>

To follow an attribute as it changes, use ``monitor``. Updates are printed when
the value changes. Stop monitoring with ``CTRL+C``.

.. code-block:: text

   wantplus-display|Heart Rate Monitor(120)| @1234> monitor <attribute_name>

Requesting a data page
^^^^^^^^^^^^^^^^^^^^^^^

The ``request`` command asks the connected sensor for a particular data page.
Specify either its page number or the corresponding data-page class name shown
by the profile. The tool displays the response if one is received, otherwise,
it reports a timeout.

.. code-block:: text

   wantplus-display|Heart Rate Monitor(120)| @1234> request <page_number>

Disconnecting
^^^^^^^^^^^^^^

Use ``disconnect`` to stop the current profile and close the active channel.

.. code-block:: text

   wantplus-display|Heart Rate Monitor(120)| @1234> disconnect
   Disconnected.


Interactive shell
-----------------

The interactive shell groups its commands around discovery, device interaction,
and monitoring. Command completion is available for several arguments, including
device numbers discovered by ``scan``, profile attributes, and data pages.

Type ``help`` for the command list or ``help <command>`` for command-specific
syntax and details.


Device discovery
^^^^^^^^^^^^^^^^^

``scan``
   Scans nearby ANT+ devices and displays their RSSI, device number, device type,
   transmission type, and profile. Press ``CTRL+C`` to stop scanning.

Device interaction
^^^^^^^^^^^^^^^^^^^

``connect <device_number>``
   Connects to the discovered ANT+ device identified by its device number.
   Decimal and ``0x`` prefixed hexadecimal numbers are accepted.

``disconnect``
   Stops the current profile and disconnects from the active ANT+ device.

``profile``
   Displays the attributes exposed by the current profile and its available
   data pages, including the fields defined for each page.

``get <attribute_name>``
   Displays the current value of a profile attribute.

``monitor <attribute_name>``
   Prints an attribute's value when it changes. Press ``CTRL+C`` to stop
   monitoring.

``request <page_number|page_class_name>``
   Requests a data page from the connected sensor. The argument can be a page
   number or a data page class name. A timeout is reported if no response is
   received.

Monitoring
^^^^^^^^^^^

``wireshark on``
   Starts Wireshark packet monitoring. When a connector is active, the monitor
   is attached to it so packets sent and received on that connection can be
   displayed.

``wireshark off``
   Detaches and closes the Wireshark monitor.

Wireshark must be installed and available to the application. If it cannot be
launched, the utility reports that the external tool is unavailable.

Exiting the utility
^^^^^^^^^^^^^^^^^^^

``quit`` or ``exit``
   Stops the active connector, closes the WHAD interface, and exits the shell.