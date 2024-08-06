Getting started
===============

Sniffing Logitech Unifying frames
---------------------------------

The :class:`whad.unifying.connector.sniffer.Sniffer` class implements a sniffer
detecting Logitech Unifying frames. This sniffer can be used to sniff frames but
also to identify compatible devices since Logitech Unifying protocol relies on
Nordic Semiconductor's *Enhanced ShockBurst* protocol.

The following snippet allows basic Logitech Unifying sniffing:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.unifying import Sniffer

    # Instantiate a compatible device
    device = WhadDevice.create('uart:/dev/ttyUSB0')

    # Wraps device with a Logitech Unifying sniffer
    sniffer = Sniffer(device)

    # Configure scanning (loop on all channels)
    sniffer.scanning = True

    # Sniff packets
    for packet in sniffer.sniff():
        packet.show()

Any Logitech Unifying frame will be shown whatever the Logitech Unifying device is.

Sniffing mouse events
^^^^^^^^^^^^^^^^^^^^^

Logitech Unifying mouse events can be specifically sniffed and interpreted through
the dedicated class :class:`whad.unifying.connector.mouselogger.Mouselogger`.
This class inherits from :class:`whad.unifying.connector.sniffer.Sniffer` and
is able to parse any packet sent by a compatible mouse. The following code
snippet will sniff any mouse event and display the corresponding interpretation:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.unifying import Mouselogger

    # Instantiate a compatible device
    device = WhadDevice.create('uart:/dev/ttyUSB0')

    # Create our mouse logger
    logger = Mouselogger(device)

    # Enable scanning
    logger.scanning = True

    # Start logging mouse event
    logger.start()

    # Display every mouse event
    for mouse_event in logger.stream():
        print(mouse_event)

This code snippet produces the following output:

.. code-block:: text

    ((24, 2), (0, 0), <ClickType.NONE: 0>)
    ((-1, -10), (0, 0), <ClickType.NONE: 0>)
    ((-6, 7), (0, 0), <ClickType.NONE: 0>)
    ((15, 1), (0, 0), <ClickType.NONE: 0>)
    ((-17, -8), (0, 0), <ClickType.NONE: 0>)
    ((18, 10), (0, 0), <ClickType.NONE: 0>)
    ((11, -2), (0, 0), <ClickType.NONE: 0>)
    ((-18, 0), (0, 0), <ClickType.NONE: 0>)
    ((-1, -3), (0, 0), <ClickType.NONE: 0>)
    ((0, 0), (0, -1), <ClickType.NONE: 0>)
    ((0, 0), (0, -1), <ClickType.NONE: 0>)
    ((0, 0), (0, 1), <ClickType.NONE: 0>)
    ((0, 0), (0, -1), <ClickType.NONE: 0>)

Sniffing keyboard events
^^^^^^^^^^^^^^^^^^^^^^^^

The same can be done with Logitech Unifying keyboards, using the dedicated
:class:`whad.unifying.connector.keylogger.Keylogger`. The following code
snippet allows sniffing and interpreting keypresses (whenever it is possible)
from an unencrypted or an encrypted keyboard:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.unifying import Keylogger

    # Instantiate a compatible device
    device = WhadDevice.create('uart:/dev/ttyUSB0')

    # Create our mouse logger
    logger = Keylogger(device)

    # Enable scanning
    logger.scanning = True

    # Start logging keyboard event
    logger.start()

    for keybd_event in logger.stream():
        print(keybd_event)


Sending Logitech Unifying frames
--------------------------------

WHAD can also be used to send specific Logitech Unifying frames to a target
dongle. Historically, Logitech refused to encrypt mouse events and therefore
all Logitech Unifying mice send their data unencrypted, allowing easy injection.
Keyboards however can use an encrypted link using a pre-shared key, therefore
injecting keystrokes requires the knowledge of an encryption key when targeting
an encrypted keyboard.

However, previous research from Bastille Research demonstrated that some encrypted
keyboards are using a Logitech Unifying dongle that accepts unencrypted keystrokes
(see `https://www.bastille.net/research/vulnerabilities/mousejack`_ ). And some
mice dongles also accept these unencrypted keystrokes as well.

Sending mouse events
^^^^^^^^^^^^^^^^^^^^

WHAD's unifying implementation provides the :class:`whad.unifying.connector.mouse.Mouse`
class that allows mouse events injection. The following code snippet shows how
to use it to target a specific mouse (with a known address):

.. code-block:: python

    from whad.device import WhadDevice
    from whad.unifying import Mouse

    # Instantiate a compatible device
    device = WhadDevice.create('uart:/dev/ttyUSB0')

    # Create our mouse injector
    mouse = Mouse(device)

    # Synchronize with our target mouse
    mouse.address = '11:22:33:44:55'
    mouse.synchronize()

    # Send a fake move (deltaX=100, deltaY=100 -- bottom right)
    mouse.move(100, 100)


Sending keyboard events
^^^^^^^^^^^^^^^^^^^^^^^

WHAD provides the :class:`whad.unifying.connector.keyboard.Keyboard` class to
interact with a Logitech Unifying keyboard. This class also supports encrypted
keyboard and can be configured to send encrypted keystrokes.

The following code snippet injects some keystrokes in an unencrypted keyboard:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.unifying import Keyboard

    # Instantiate a compatible device
    device = WhadDevice.create('uart:/dev/ttyUSB0')

    # Create our keyboard injector
    kbd = Keyboard(device)

    # Synchronize with our target keyboard
    kbd.address = "11:22:33:44:55"
    kbd.synchronize()

    # Send a series of keystrokes
    kbd.send_text("Hello, world !")
