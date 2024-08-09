Compatible devices
==================

Hardware devices
----------------

The following chart summarizes the various hardware devices supported by WHAD
by running custom firmware:

+--------------------------+-----+---------+-----+-----+----------+
| Device                   | BLE | Dot15d4 | ESB | PHY | Unifying |
+==========================+=====+=========+=====+=====+==========+
| :ref:`dev-md-nrf52`      | X   | X       | X   | X   | X        |
+--------------------------+-----+---------+-----+-----+----------+
| :ref:`dev-ns-nrf52`      | X   | X       | X   | X   | X        |
+--------------------------+-----+---------+-----+-----+----------+
| SeeedStudio LoRa-e5-Mini |     |         |     | X   |          |
+--------------------------+-----+---------+-----+-----+----------+
| STM32 Nucleo-WL55        |     |         |     | X   |          |
+--------------------------+-----+---------+-----+-----+----------+
| Espressif ESP32-WROOM    | X   |         |     |     |          |
+--------------------------+-----+---------+-----+-----+----------+

Virtual devices
---------------

The following chart summarizes the various devices that are supported by WHAD
through an adaptation layer:

+--------------------------+-----+---------+-----+-----+----------+
| Device                   | BLE | Dot15d4 | ESB | PHY | Unifying |
+==========================+=====+=========+=====+=====+==========+
| Bluetooth HCI adapter    | X   |         |     |     |          |
+--------------------------+-----+---------+-----+-----+----------+
| APIMote                  |     | X       |     |     |          |
+--------------------------+-----+---------+-----+-----+----------+
| Bastille RFStorm         |     |         | X   | X   | X        |
+--------------------------+-----+---------+-----+-----+----------+
| ATMEL RZUSBSTICK         |     | X       |     |     |          |
+--------------------------+-----+---------+-----+-----+----------+
| Yard Stick One           |     |         |     | X   |          |
+--------------------------+-----+---------+-----+-----+----------+
| Ubertooth One            | X   |         |     |     |          |
+--------------------------+-----+---------+-----+-----+----------+


.. _dev-md-nrf52:

Makerdiary nRF52840 MDK USB Dongle
----------------------------------

The *nRF52840 MDK USB Dongle* is a nRF52-based development kit in the form of
an USB stick. It is based on Nordic Semiconductor's nRF52840 SoC that is fully
compatible with WHAD.

How to buy one
^^^^^^^^^^^^^^

The Makerdiary's nRF52840 MDK USB Dongle is sold by Amazon, SeeedStudio,
Tindie and Makerdiary (see `their official purchase page <https://wiki.makerdiary.com/nrf52840-mdk-usb-dongle/purchase/>`_). It costs around $22 USD.

Installing *Butterfly* firmware on an nRF52840 MDK dongle
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Follow this procedure to install a WHAD-compatible firmware on this device:

1. Download the latest version of Butterfly for nRF52840 MDK USB Dongle
2. Plug your nRF52840 MDK USB dongle into your computer
3. Press the tactile switch during 2 seconds and release, a red LED must blink
4. Access with a file explorer the new mass storage device and copy the firmware update file into it

.. _dev-ns-nrf52:

Nordic's nRF52840 Dongle
------------------------

Nordic's nRF52840 dongle is pretty similar to Makerdiary's nR52840 MDK dongle,
and costs around $10 USD.

How to buy one
^^^^^^^^^^^^^^



Installing *Butterfly* firmware on a Nordic nRF52840 Dongle
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^


