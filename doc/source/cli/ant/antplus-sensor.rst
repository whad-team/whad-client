wantplus-sensor: ANT+ Sensor Emulator
======================================


`wantplus-sensor` is a WHAD utility designed to emulate ANT+ sensors, 
configure their profile attributes, manage transmission, and monitor data 
or packets in real time. 

It provides an interactive shell to inspect profile properties, modify local attributes, force 
data page transmissions, and optionally observe packets using Wireshark.

The tool requires a WHAD-compatible interface capable of communicating with ANT+ devices.

.. contents:: Table of Contents
   :local:
   :depth: 2

Usage
-----

Start the utility by specifying the WHAD interface and optionally the target device type, device number, or transmission type:

.. code-block:: text

   $ wantplus-sensor -i  [-t ] [-n ]

For example:

.. code-block:: text

   $ wantplus-sensor -i uart -t 120
   wantplus-sensor>

The application defines several command-line arguments:

* `--device-type` (`-t`): Specifies the ANT+ device type (default: `120`, representing a Heart Rate Monitor).
* `--device-number` (`-n`): Specifies the unique device number (default: `1234`).
* `--transmission-type`: Specifies the ANT+ transmission type (default: `1`).
* `--file` (`-f`): Specifies a script file to execute automatically.

When the interactive shell is open, type `help` to list available commands or `help <command>` for detailed information on a specific command.

Quick tutorial
--------------

This tutorial outlines a typical workflow: configuring or starting a sensor, inspecting its profile, modifying local attributes, and forcing data pages.

Starting the sensor
^^^^^^^^^^^^^^^^^^^^

Use `start` to initialize and start broadcasting as an ANT+ sensor based on the loaded profile.

.. code-block:: text

   wantplus-sensor> start
   Started Heart Rate Monitor (device number 1234, device type 120).

Once started, the prompt updates to reflect the active profile name, device type, and device number.

Inspecting a profile
^^^^^^^^^^^^^^^^^^^^^

The `profile` command lists all available profile attributes (along with their current values) and supported data pages with their respective fields.

.. code-block:: text

   wantplus-sensor|Heart Rate Monitor(120)| @1234> profile


To read a single attribute value, use `get`:

.. code-block:: text

   wantplus-sensor|Heart Rate Monitor(120)| @1234> get <attribute_name>


To modify a local attribute value dynamically, use `set`:

.. code-block:: text

   wantplus-sensor|Heart Rate Monitor(120)| @1234> set <attribute_name> 


To monitor an attribute for local changes in real time, use `monitor`. Stop monitoring with `CTRL+C`.

.. code-block:: text

   wantplus-sensor|HeartRate Monitor(120)| @1234> monitor <attribute_name>

Sending a data page manually
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The `send` command forces the sensor to transmit a specific data page immediately. You can specify either its page number or its class name.

.. code-block:: text

   wantplus-sensor|Heart Rate Monitor(120)| @1234> send <page_number|page_class_name>

Stopping and disconnecting
^^^^^^^^^^^^^^^^^^^^^^^^^^^


Use `stop` to halt sensor transmission and close the active channel.

.. code-block:: text

   wantplus-sensor|Heart Rate Monitor(120)| @1234> stop
   Sensor stopped.

Interactive shell
-----------------

The interactive shell organizes commands into categories such as **Device interaction** and 
**Monitoring**. Command completion is supported for arguments like profile attributes and 
data page identifiers.

Type `help` for the command list or `help <command>` for syntax details.

Device interaction
^^^^^^^^^^^^^^^^^^^

`start`
   Initializes and starts the ANT+ sensor simulation using the current device parameters and profile.

`stop`
   Stops the active ANT+ sensor transmission and closes the connection channel.

`profile`
   Displays the attributes, current values, and available data pages (with field details) exposed by the current sensor profile.

`get <attribute_name>`
   Displays the current value of a specific profile attribute.

`set <attribute_name> <value>`
   Updates the value of a profile attribute on the fly.

`monitor <attribute_name>`
   Continuously monitors and prints local attribute updates as they change. Press `CTRL+C` to exit.

`reset`
   Resets all profile attributes back to their default initial values.

`send <page_number|page_class_name>`
   Forces the sensor to transmit a specified data page immediately.

Monitoring
^^^^^^^^^^^

`wireshark on`
   Launches and attaches Wireshark to monitor packets sent and received by the active sensor channel.

`wireshark off`
   Detaches and closes the Wireshark monitoring session.

**Note:** Wireshark must be installed and accessible on your system path. If unavailable, the tool will report an error.

Exiting the utility
^^^^^^^^^^^^^^^^^^^

`quit` or `exit`
   Stops any active transmission, closes the WHAD interface, and exits the application shell.