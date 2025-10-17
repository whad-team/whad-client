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


