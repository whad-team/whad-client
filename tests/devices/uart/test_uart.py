"""UART device unit tests: interface strings and serial port selection."""

import os
from types import SimpleNamespace

import pytest

import whad.device.uart as uart_module
from whad.device import Device
from whad.device.uart import Uart
from whad.exceptions import WhadDeviceNotFound

# USB IDs (VID, PID, manufacturer, product) of a supported ButteRFly dongle,
# and of a USB-serial bridge (2886:0068) that is not in SUPPORTED_UART_DEVICES
BUTTERFLY = (0xc0ff, 0xeeee, "WHAD", "ButteRFly dongle")
BRIDGE = (0x2886, 0x0068, None, None)


def usb_port(device, usb_ids):
    """Describe a USB CDC ACM serial port the way `comports()` does."""
    vid, pid, manufacturer, product = usb_ids
    return SimpleNamespace(device=device, vid=vid, pid=pid,
                           manufacturer=manufacturer, product=product,
                           subsystem="usb")


@pytest.fixture
def serial_ports(monkeypatch):
    """Serial ports as `comports()` lists them: two supported ButteRFly
    dongles, and three ports behind the unsupported bridge, one of them with
    colons in its name."""
    listed = [
        usb_port("/dev/ttyACM0", BUTTERFLY),
        usb_port("/dev/ttyACM1", BRIDGE),
        usb_port("/dev/ttyACM2", BUTTERFLY),
        usb_port("COM3", BRIDGE),
        usb_port("/dev/whad:usb-0:1:1.0", BRIDGE),
    ]
    monkeypatch.setattr(uart_module, "comports", lambda: listed)
    Uart.reset_dev_index()


@pytest.fixture
def pty_port(request, monkeypatch, tmp_path):
    """A pseudo-terminal that `comports()` lists under the USB IDs given as
    parameter, and a symbolic link to it with colons in its name, like the
    links udev creates in /dev/serial/by-path/."""
    termios = pytest.importorskip("termios")
    master, slave = os.openpty()
    port = os.ttyname(slave)
    link = tmp_path / "pci-0000:00:14.0-usb-0:1:1.0"
    link.symlink_to(port)
    monkeypatch.setattr(uart_module, "comports",
                        lambda: [usb_port(port, request.param)])
    Uart.reset_dev_index()

    def line_speeds():
        """The input and output speeds the kernel reports for the port."""
        attrs = termios.tcgetattr(slave)
        return attrs[4], attrs[5]

    def speed(baudrate):
        """The termios speed for a baud rate."""
        return getattr(termios, f"B{baudrate}")

    yield SimpleNamespace(name=port, link=str(link),
                          line_speeds=line_speeds, speed=speed)
    os.close(master)
    os.close(slave)


@pytest.mark.usefixtures("serial_ports")
def test_list_only_supported_devices():
    """Enumeration keeps filtering ports on their USB IDs."""
    listed = [dev.identifier for dev in Uart.list()]
    assert listed == ["/dev/ttyACM0", "/dev/ttyACM2"]


@pytest.mark.parametrize("interface, port", [
    ("uart", "/dev/ttyACM0"),
    ("uart0", "/dev/ttyACM0"),
    ("uart1", "/dev/ttyACM2"),
])
@pytest.mark.usefixtures("serial_ports")
def test_index_selects_supported_device(interface, port):
    """`uart` and `uartN` only select supported devices."""
    assert Device.create(interface).identifier == port


@pytest.mark.usefixtures("serial_ports")
def test_index_skips_unsupported_device():
    """An unsupported port is never selected by index."""
    with pytest.raises(WhadDeviceNotFound):
        Device.create("uart2")


@pytest.mark.parametrize("interface, port", [
    ("uart:/dev/ttyACM0", "/dev/ttyACM0"),
    ("uart:/dev/ttyACM1", "/dev/ttyACM1"),
    ("uart:/dev/ttyACM0:115200", "/dev/ttyACM0"),
    ("uart:/dev/ttyACM1:230400", "/dev/ttyACM1"),
    ("uart:/dev/ttyACM1:2147483647", "/dev/ttyACM1"),
    ("uart:COM3", "COM3"),
    ("uart:COM3:921600", "COM3"),
    ("uart:/dev/whad:usb-0:1:1.0", "/dev/whad:usb-0:1:1.0"),
    ("uart:/dev/whad:usb-0:1:1.0:230400", "/dev/whad:usb-0:1:1.0"),
])
@pytest.mark.usefixtures("serial_ports")
def test_named_port(interface, port):
    """A named port is used regardless of its USB IDs, with an optional baud
    rate, and may have colons in its name."""
    dev = Device.create(interface)
    assert isinstance(dev, Uart)
    assert dev.identifier == port


@pytest.mark.usefixtures("serial_ports")
def test_named_supported_port_is_listed_instance():
    """A supported device named without a baud rate is the listed one."""
    assert Device.create("uart:/dev/ttyACM2").interface == "uart1"


@pytest.mark.parametrize("interface", [
    "uart:",
    "uart:/dev/ttyACM9",
    "uart:/dev/ttyACM9:230400",
    "uart:/dev/ttyACM1:0",
    "uart:/dev/ttyACM1:fast",
    "uart:/dev/ttyACM1:2147483648",
    "uart:/dev/ttyACM1:99999999999999999999999",
])
@pytest.mark.usefixtures("serial_ports")
def test_named_port_not_found(interface):
    """A port that does not exist is not found, baud rate or not. A trailing
    field that is not a valid baud rate is part of the port name."""
    with pytest.raises(WhadDeviceNotFound):
        Device.create(interface)


@pytest.mark.parametrize("pty_port", [BRIDGE, BUTTERFLY],
                         ids=["unsupported", "supported"], indirect=True)
@pytest.mark.parametrize("named_by", ["name", "link"])
@pytest.mark.parametrize("suffix, baudrate", [
    ("", 115200),
    (":230400", 230400),
])
def test_named_port_opens_at_baudrate(pty_port, monkeypatch, named_by, suffix,
                                      baudrate):
    """Open a port, supported or not, by its name or through a symbolic link,
    and check the line speed the kernel reports for it."""
    # Only open the serial port: no I/O threads, no reset handshake.
    monkeypatch.setattr(Device, "open", lambda self: None)

    dev = Device.create(f"uart:{getattr(pty_port, named_by)}{suffix}")
    dev.open()
    try:
        speeds = pty_port.line_speeds()
    finally:
        dev.close()
    assert dev.identifier == pty_port.name
    assert speeds == (pty_port.speed(baudrate),) * 2


@pytest.mark.parametrize("pty_port", [BUTTERFLY], ids=["supported"],
                         indirect=True)
def test_link_to_supported_port_is_listed_instance(pty_port):
    """A link is resolved before the lookup: a supported device named through
    one without a baud rate is the listed one."""
    dev = Device.create(f"uart:{pty_port.link}")
    assert dev.identifier == pty_port.name
    assert dev.interface == "uart0"
