Getting started
===============

The PHY domain is dedicated to low-level modulation and demodulation. This
domain allows sending a series of bytes from the host to any wireless device
as well as receiving bytes sent by any wireless device with a compatible WHAD
interface.

The following modulation/demodulation are supported by the WHAD protocol, but
not by all WHAD adapters:

- Amplitude Shift Keying / On/Off Keying (*ASK* / *OOK*)
- Frequency Shift Keying (*FSK*)
- Four Frequency Shift Keying (*4FSK*)
- Gaussian Frequency Shift Keying (*GFSK*)
- Minimum-Shift Keying (*MSK*)
- Quadrature Phase-Shift Keying (*QPSK*)
- Binary Phase-Shift Keying (*BPSK*)
- *LoRa*

Sniffing raw packets
--------------------

The :class:`whad.phy.connector.sniffer.Sniffer` class wraps the demodulating
logic and must be used to sniff raw demodulated data. This sniffer must be
configured through a dedicated :class:`whad.phy.sniffing.SnifferConfiguration`
instance that will determine the demodulation and its parameters.

First, we need to create an instance of this class to hold our mod/demod
parameters:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.phy import SnifferConfiguration, Sniffer

    # Create our WHAD device
    device = WhadDevice.create('uart:/dev/ttyUSB0')

    # Create our sniffing configuration
    config = SnifferConfiguration()


Setting the target frequency
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Setting the target frequency (in *Hertz*) is pretty simple:

.. code-block:: python

    # Configure demodulation
    config.frequency = 2402000000

In our case, we are going to sniff on *2.402* GHz (2.402.000.000 Hz).

Setting the modulation and its parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Modulation is specified by setting the correct boolean in :class:`SnifferConfiguration`.
In our case, we want to use a GFSK demodulation so we set the ``gfsk`` property
to ``True``:

.. code-block:: python

    # Configure demodulation
    config.frequency = 2402000000
    config.gfsk = True

Frequency-shift keying modulation requires more parameters to be set, including:

- *deviation* (in *Hertz*): this value indicates the frequency deviation
- *datarate* (in bits per second): this value specifies the communication speed

We want to demodulate a signal with a deviation of 250 kHz with a datarate of 1 Mbps:

.. code-block:: python

    # Configure demodulation
    config.frequency = 2402000000
    config.gfsk = True
    config.deviation = 250000
    config.datarate = 1000000


Setting endianness and size
^^^^^^^^^^^^^^^^^^^^^^^^^^^

During digital demodulation, encoded bits are grouped by 8 to form bytes and
these bytes are grouped to form a raw packet. We need to tell the demodulator
the bit order to use (either *little-endian* or *big-endian*). *Little-endian*
indicates that the least-significant bit (LSB) is sent first while *big-endian*
indicates that the most-significant bit (MSB) is sent first. Last but not least,
we must give the demodulator a maximum packet size as this latter is not able
to stream raw demodulated data (but only chunks of data stored in packets).

We want bytes with LSB first, for a maximum size of 128 bytes per packet:

.. code-block:: python

    # Configure demodulation
    config.frequency = 2402000000
    config.gfsk = True
    config.datarate = 1000000
    config.little_endian = True
    config.fsk_configuration.deviation = 250000
    config.packet_size = 128

Setting synchronization word
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Usually, a demodulator looks for a specific series of bits that are expected to
mark the beginning of a frame or a packet. This series of bits is called a
*synchronization word*, or *sync word* in short. It can be configured as well,
but by default, it is set to a byte made of atlernating 0s and 1s: 0xAA. 

We can use another synchronization word, like 0xF00D:

.. code-block:: python

    # Configure demodulation
    config.frequency = 2402000000
    config.gfsk = True
    config.datarate = 1000000
    config.little_endian = True
    config.fsk_configuration.deviation = 250000
    config.packet_size = 128
    config.sync_word = b"\x0D\xF0" # little-endian

Sniffing demodulated raw packets
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When all parameters are correctly set, the configuration can be passed to our
sniffer in order to demodulate data:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.phy import SnifferConfiguration, Sniffer

    # Create our WHAD device
    device = WhadDevice.create('uart:/dev/ttyUSB0')

    # Create our sniffing configuration
    config = SnifferConfiguration()

    # Configure demodulation
    config.frequency = 2402000000
    config.gfsk = True
    config.datarate = 1000000
    config.little_endian = True
    config.fsk_configuration.deviation = 250000
    config.packet_size = 128
    config.sync_word = b"\x0D\xF0" # little-endian

    # Create a sniffer based on our configuration
    sniffer = Sniffer(device)
    sniffer.configuration = configuration

Last but not least, we ask our sniffer to capture packets and report them:

.. code-block:: python

    # Start sniffer
    sniffer.start()

    # Demodulate raw packets
    for packet in sniffer.sniff():
        packet.show()


Sending raw packets
-------------------

Raw packets can be sent pseudo-synchronously or asynchronously, depending on the
need. Pseudo-synchronous packets are sent as soon as possible, depending on the
hardware and the latency caused by the host/interface communication. Asynchronous
packets are far more precise but need to be prepared and fed into the hardware
enough time before sending.

In order to transmit a raw packet, we need to use the default :class:`whad.phy.connector.PHY`
class and set the modulation parameters as we did above with our sniffer. For
instance, to send GFSK raw packets with a *sync word* of 0xF00D on 2.402 GHz,
a deviation of 250 kHz and a datarate of 1 Mbps, we use the following code:

.. code-block:: python

    from whad.device import WhadDevice
    from whad.phy import Phy, endianness

    # Create our whad device
    device = WhadDevice.create("uart0")

    # We wrap it with our connector
    phy = PHY(device)

    # Configure our transmitter
    phy.set_frequency(2402000000)
    phy.set_gfsk(deviation=250000)
    phy.set_datarate(1000000)
    phy.set_endianness(Endianness.LITTLE)
    phy.set_sync_word(b"\x0D\x0F)


Pseudo-synchronous packet transmission
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To send a pseudo-synchronous packet, we simply use the :func:`whad.phy.connector.PHY.send`
function:

.. code-block:: python

    phy.send(b"Hello, World !")

.. warning::

    There is no certainty the hardware will send the packet as soon as it receives
    the command corresponding to the packet transmission, but it will do its best
    to send it as soon as possible.

    This is a known limitation of WHAD's design that can be solved with scheduled
    packets (see below).


Asynchronous packet transmission
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

It is also possible to tell the hardware when to send a packet with a precision
of about a microsecond by using a *scheduled packet*. Scheduled packets are
packets that are sent ahead of the real transmission, saved into the hardware
and sent at the expected time with no delay.

To send such a packet, we need to prepare it and send it to our WHAD device:

.. code-block:: python

    phy.schedule_send(b"Hello, World!", timestamp=1515.0)

The hardware may have a limited number of slots for scheduled packets and this
code may raise the :class:`whad.phy.exceptions.ScheduleFifoFull` exception if
all the slots are already set.

Packet will be transmitted at the specified timestamp and a notification sent
to the connector.