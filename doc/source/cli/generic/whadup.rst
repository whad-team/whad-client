whadup: WHAD device information
===============================

*Whadup* is a convenient tool to enumerate all your WHAD devices plugged into
your computer and find out what they are capable of as well as other valuable
information.

Enumerate plugged WHAD devices
------------------------------

When you simply run ``whadup``, this tool will try to enumerate every connected
WHAD device and will show some basic information about them. An example output
of this tool is presented below.

.. code-block:: text

    # whadup
    [i] Available devices
    - hci0
      Type: HCIDevice
      Index: 0
      Identifier: hci0

    - hci1
      Type: HCIDevice
      Index: 1
      Identifier: hci1

    - uart0
      Type: UartDevice
      Index: 0
      Identifier: /dev/ttyUSB0

Get detailed information on a WHAD device
-----------------------------------------

If you specify a WHAD device in the first argument, it will connect to this device
and gather more information about its supported domains, capabilities, and much more:

.. code-block:: text

    # whadup uart0
    [i] Connecting to device ...
    [i] Device details

    Device ID: 65:73:70:33:32:5f:37:65:64:35:61:32:00:00:00:00
    Firmware info: 
    - Author : Damien Cauquil
    - URL    : https://github.com/virtualabs/esp32-fw.git
    - Version: 1.0.0

    [i] Discovering domains ...
    [i] Domains discovered.

    This device supports Bluetooth LE:
    - can inject packets
    - can simulate a role in a communication
    - can not read/write raw packet

    List of supported commands:
    - SetBdAddress: can set BD address
    - ScanMode: can scan devices
    - AdvMode: can advertise as a BLE device
    - CentralMode: can act as a Central device
    - ConnectTo: can initiate a BLE connection
    - SendPDU: can send a raw PDU
    - Disconnect: can terminate an active connection (in Central mode)
    - PeripheralMode: can act as a peripheral
    - Start: can start depending on the current mode
    - Stop: can stop depending on the current mode

This tool retrieves the following information:

* *Device ID*: a unique identifier associated with the WHAD device
* *Firmware information*: shows the firmware's URL, version and author(s)
* *Available domains with supported roles and commands* for each of them