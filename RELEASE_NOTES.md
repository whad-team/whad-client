Release notes for versions 1.2.12
=================================

Bugfixes
--------

- Fixed HID key codes for BE keymap
- Fixed right-hand side ALT,SHIFT and CTRL key
- Fixed interactive shell prompt (missing whitespace before command)
- Fixed a bug in `wble-central` that caused a crash when reading a characteristic with an invalid offset
- Fixed connection attempt cancelation in HCI virtual device (BLE-related)
- Fixed a regression in `wble-connect` and `wble-spawn`
- Fixed a bug in WHAD's `Device` class that made the associated device index goes off
- Fixed multiple bugs in WHAD's BLE stack

New features
------------

### Bluetooth Low Energy Central API has been improved

In previous versions, once a connection to a target device established (an instance of `PeripheralDevice`), accessing a characteristic from 
a service was done as follows:

```python
my_char = remote_device.get_characteristic(UUID('1800'), UUID('2A00'))
if my_char is not None:
    print("Characteristic 2A00 has been found !")
else:
    print("No characteristic 2A00 found.")
```

This syntax is still supported to avoid a breaking change (and will be deprecated in the future), but
version 1.2.12 introduces new methods to get a simpler and more concise syntax:

```python
my_char = remote_device.char('2A00', '1800')
if my_char is not None:
    print("Characteristic 2A00 has been found !")
else:
    print("No characteristic 2A00 found.")
```

The new `char()` method has been designed to be really flexible and accepts UUIDs as strings or `UUID`
objects, with the service UUID (the second parameter in the example above, `1800`) being optional. In fact,
very few devices use identical characteristics' UUIDs in two or more different services. A shorter form
of the previous code could be:

```python
my_char = remote_device.char('2A00')
if my_char is not None:
    print("Characteristic 2A00 has been found !")
else:
    print("No characteristic 2A00 found.")
```

A similar change has been made to provide the `service()` method that now accepts the requested UUID as a string
or an instance of `UUID`:

```python
my_service = remote_device.service('1800')
```

### Bluetooth Low Energy standard services

The Bluetooth specification defines a set of _standard services_ with for each of them a set of associated mandatory
and optional characteristics, like the _Battery Service_ or the _Heart Rate Service_. Starting from version 1.2.12,
we added a feature to make interaction with such services easier:

```python
from whad.device import Device
from whad.ble import Central, UUID, BatteryService
from whad.ble.exceptions import PeripheralNotFound

# We assign a BLE central role to our HCI adapter
central = Central(Device.create("hci0"))

# Target not connected
target = None

try:
    # Connect to remote device and discover services and characteristics
    target = central.connect("00:11:22:33:44:55", random=True)
    target.discover()

    # Check the device exposes a Battery service, queries it and read
    # the battery's level as a percentage
    if target.has(BatteryService):
        battery = target.query(BatteryService)
        print(f"Battery level: {battery.percentage}%")
    else:
        print("Battery service is not supported by this device.")

    # Closing connection
    target.disconnect()

# Handle connection error
except PeripheralNotFound:
    print("Target device not found.")
```

To check if a given standard service is supported by a device (i.e. if it provides at least the associated GATT
service and defined mandatory characteristics), we simply use the `has()` method:

```python
    if target.has(BatteryService):
        # continue with target device
    else:
        # service is not supported
```

This method returns `True` if the requested service is supported. If so, we can retrieve an instance of this standard
service tied to our remote device and access some of its properties, like for instance the `percentage` property of
`BatteryService`:

```python
    # Check the device exposes a Battery service, queries it and read
    # the battery's level as a percentage
    if target.has(BatteryService):
        battery = target.query(BatteryService)
        print(f"Battery level: {battery.percentage}%")
    else:
        print("Battery service is not supported by this device.")
```

We provide the following default standard services:

- Battery Service
- Heart Rate Service
- Device Information Service

More standard services are expected to be implemented in the future, feel free to contribute and send us a pull request
to add more services! See documentation and code for implementation details.


Release notes for version 1.2.11
================================

Bugfixes
--------

- Logitech Unifying HID decoding has been improved and some related bugs fixed
- Global loading and processing time of the whole framework has been improved through lazy loading and other optimizations
- BLE sniffer and scanner connectors have been improved to support Python's `with` statement
- `wanalyze` documentation has been updated to reflect recently added options (`--set`)

New features
------------

This section details the new features introduced in version 1.2.11.

### Bluetooth Low Energy scanner and sniffer now supports contextual managers

Starting from version 1.2.11, Bluetooth Low Energy `Scanner` and `Sniffer` connectors
support Python's contextual managers through the use of a `with` statement. When used
in a `with` statement, these connectors handle transparently the hardware they are
associated with by automatically configuring, starting and stopping the associated
mode.

Scanning for BLE devices is now pretty easy to do, and more readable:

```python
from whad.device import Device
from whad.ble import Scanner

with Scanner(Device.create("hci0")) as scanner:
    for device in scanner.discover_devices():
        print(device)
```

### New IEEE 802.15.4 DLTs supported by wplay

Previous versions were only able to read PCAP files containing IEEE 802.15.4 frames stored
using the `LINKTYPE_IEEE802_15_4_TAP` format (type 283), this version adds support of the following
link types:

- `LINKTYPE_IEEE802_15_4_LINUX` (191)
- `LINKTYPE_IEEE802_15_4_WITHFCS` (195)
- `LINKTYPE_IEEE802_15_4_NONASK_PHY` (215)
- `LINKTYPE_IEEE802_15_4_NOFCS` (230)

### Improved performance

Version 1.2.11 also improves performance of the whole framework. We identified some bottlenecks
that led the framework to take seconds to completely load and modified the way it works to
significantly speed up its loading time. Its post-execution cleanup code has also been
improved to reduce the latency observed with most command-line tools when they were terminating.


Important changes
-----------------

Some changes made in this version introduce impact the way some components behave and the
data they consume or produce. This section provide a comprehensive overview of those major
modifications and their impact on scripts or applications that use them.

### HID ALT key

The Logitech Unifying HID converter component used by the `keystroke` traffic analyzer in `wanalyze`
has been updated to differentiate both left-hand side and right-hand side `ALT` keys, now returning
`LALT` as the textual description of the left-hand side `ALT` key and `RALT` for the right-hand side
`ALT` key instead of the single `ALT` text it previously returned for both. This may break scripts
or applications that rely on the previous `ALT` textual representation of those keys and they shall
be modified to handle these two new names.

### WHAD scapy layers

Previous versions of WHAD automatically loaded a set of custom *Scapy* layers for every supported
protocol, impacting the framework loading time. Starting from version 1.2.11, WHAD now relies on
lazy loading through its *protocol hub* component to load those layers whenever it is required,
optimizing the loading time and providing a smoother experience.

Applications or scripts that rely on these layers without WHAD's *protocol hub* need to explicitely
load these layers instead of simply importing all of them by using a ``from whad.scapy.layers import *``
statement. For instance, an application requiring WHAD's custom layers for Bluetooth Low Energy
shall now import the corresponding layers:

```python
from whad.scapy.layers.bluetooth import *
```

### `WhadDevice` renamed to `Device`

When accessing a compatible hardware with WHAD, previous versions used the `WhadDevice` class
to retrieve an object representing a specific interface:

```python
from whad.device import WhadDevice

dev = WhadDevice.create("uart0")
```

The `WhadDevice` class has been renamed to `Device` for simplicity, but the previous class is
kept for compatibility. The recommended way to access WHAD hardware interfaces is the following:

```python
from whad.device import Device

dev = Device.create("uart0")
```

The `WhadDevice` class will be deprecated in a future version, and is planned to be later removed.
When deprecated, the framework will display a warning message whenever this class is used to warn
about the upcoming removal. No planning has been defined yet for this deprecation and future removal,
but we will communicate about it when one had been decided.


