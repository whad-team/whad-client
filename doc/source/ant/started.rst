Getting started
===============

*ANT* is a proprietary wireless communication protocol designed by Dynastream Innovations (bought by Garmin) and supported by a set of wireless system-on-chips including
the *nRF24* and *nRF5x* series. 

It is mainly used by sport and health oriented sensors & displays, such as Heart Rate Monitor (HRM) or Bicycle Candence & Speed sensors.

While the ANT protocol defines the lowest part of the protocol stack, two additional applicative layers can be instantiated on top of ANT:
    - *ANT+*, a set of profiles standardizing the communication between low energy sensors
    - *ANT-FS*, a file sharing protocol built over ANT

See `This is ANT website <https://thisisant.com>`_ for more details.

Scan available devices
----------------------

Use the :class:`whad.ant.connector.scanner.Scanner` class to instantiate
a ANT device scanner and detect all the available devices.

.. code-block:: python

    from whad import UartDevice
    from whad.ant import Scanner

    scanner = Scanner(WhadDevice.create('uart0'))
    scanner.start()

    for device in scanner.discover_devices():
        print(device)


The :meth:`whad.ant.connector.scanner.Scanner.discover_devices` method can be filtered to select specific ANT packet fields:
    - *device_type* 
    - *device_number*
    - *transmission_type* 

For example, the following code snippet discover only devices matching the condition `transmission_type = 1` & `device_type = 120` (e.g. ANT+ HRM).

.. code-block:: python

    for device in scanner.discover_devices(device_type=120, transmission_type=1):
        print(device)


A *timeout* value can also be provided to automatically terminates the scan after a specific duration (in seconds):

.. code-block:: python

    # Terminates after three seconds
    for device in scanner.discover_devices(timeout = 3):
        print(device)


Finally, it's also possible to take potential updates into account (re-yielding the device) by altering the *updates* indicator:


.. code-block:: python

    # Yield the device again if its state has been updated
    for device in scanner.discover_devices(updates = True):
        print(device)



A discovered device is implemented as a :class:`whad.ant.scanning.ANTDiscoveredDevice` object. It can be manipulated easily using its property:


.. code-block:: python
    
    for device in scanner.discover_devices():
        print("The following device has been discovered:")
        print("  - Device number: ", device.device_number)
        print("  - Device type: ", device.device_type)
        print("  - Transmission type: ", device.transmission_type)
        print("  - RSSI: ", device.rssi)
        print("  - List of RF channels: ", device.channels)
        print("  - Last RF channel: ", device.last_channel)
        print("  - Last observed payload: ", device.last_payload)
        print("  - Last observed timestamp: ", device.last_timestamp)
        print()
