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
| :ref:`dev-lora-e5`       |     |         |     | X   |          |
+--------------------------+-----+---------+-----+-----+----------+
| :ref:`dev-stm32wl`       |     |         |     | X   |          |
+--------------------------+-----+---------+-----+-----+----------+
| :ref:`dev-esp32-wroom`   | X   |         |     |     |          |
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

Where to buy
^^^^^^^^^^^^

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

Nordic nRF52840 Dongle
----------------------

Nordic nRF52840 dongle is pretty similar to Makerdiary's nR52840 MDK dongle,
and costs around $10 USD.

Where to buy
^^^^^^^^^^^^

Nordic nRF52840 dongle can be purchased on various resellers websites as listed on
`Nordic nRF52840 website <https://www.nordicsemi.com/Products/Development-hardware/nRF52840-Dongle>`_.


Installing *Butterfly* firmware on a Nordic nRF52840 Dongle
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Follow this procedure to install a WHAD-compatible firmware on this device:

1. Download the latest version of Butterfly built for Nordic nRF52840 dongle
2. Download and install Nordic *nrfutil* on your computer
3. Plug your Nordic nRF52840 dongle in your computer and press the *RESET* button for 2 seconds
4. Make sure a red LED blinks before continuing with next steps. If not retry step 4.
5. Execute the following command to upload the firmware into the dongle: `` nrfutil dfu usb-serial -pkg butterfly-nordic-latest.zip -p SERIAL_PORT -b 115200`` (replace SERIAL_PORT with your device serial port)


.. _dev-lora-e5:

SeeedStudio LoRa-e5-Mini
------------------------

SeeedStudio LoRa-e5-Mini dongle is produced by SeeedStudio and its cost is really attractive.
This dongle is based on SeeedStudio's Wio-e5 module that relies on an STM32WLE5 system-on-chip.

Where to buy
^^^^^^^^^^^^

SeeedStudio LoRa-e5-Mini are available for around $22 USD on `SeeedStudio website <https://www.seeedstudio.com/LoRa-E5-mini-STM32WLE5JC-p-4869.html>`_.

Installing a WHAD-compatible firmware
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. attention::

    This section will be completed pretty soon, firmware is available in our `STM32WL dedicated repository <https://github.com/whad-team/stm32wlxx-firmware>`_

.. _dev-stm32wl:

STM32WL55 Nucleo board
----------------------

This board is a development board produced and sold by ST Microelectronics based on a STM32WL55 system-on-chip.

Where to buy
^^^^^^^^^^^^

Directly on `ST Microelectronics online store <https://estore.st.com/en/products/evaluation-tools/product-evaluation-tools/mcu-mpu-eval-tools/stm32-mcu-mpu-eval-tools/stm32-nucleo-boards/nucleo-wl55jc.html>`_
or its affiliates, for around $41 USD.

Installing a WHAD-compatible firmware
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. attention::

    This section will be completed pretty soon, firmware is available in our `STM32WLXX dedicated repository <https://github.com/whad-team/stm32wlxx-firmware>`_

.. _dev-esp32-wroom:

Espressif ESP32-WROOM
---------------------

ESP32-WROOM is a development board designed by Espressif that includes a 240 Mhz capable dual-core CPU and WiFi and
Bluetooth Low Energy capabilities. We developed a compatible firmware but it's still experimental. It's kinda working
but needs sone adjustments to be really stable, so expect some disconnections.

Where to buy
^^^^^^^^^^^^

ESP32-WROOM are widely available, sold on Amazon or AliExpress for around $10 USD.

Install a WHAD-compatible firmware
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. attention::

    This section will be completed pretty soon, firmware is available in our `NodeMCU dedicated repository <https://github.com/whad-team/nodemcu-esp32-firmware>`_. Build instructions included in README, well for what it's worth.
