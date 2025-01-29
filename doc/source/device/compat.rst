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

Installing *Butterfly* firmware on an nRF52840 MDK dongle (UF2 Bootloader)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Follow this procedure to install a WHAD-compatible firmware on this device:

1. Download the `latest version <https://github.com/whad-team/butterfly/releases/latest>`_ of Butterfly for nRF52840 MDK USB Dongle (UF2 file).
2. Push and hold the button and plug your dongle into the USB port of your computer. Release the button after your dongle is connected. The RGB LED turns green.
3. It will mount as a Mass Storage Device called UF2BOOT.
4. Access with a file explorer the new mass storage device and copy the firmware update file into it.
5. Replug your dongle to run the new firmware.


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

1. Download the `latest version <https://github.com/whad-team/butterfly/releases/latest>`_ of Butterfly built for Nordic nRF52840 dongle (zip archive).
2. Download and install Nordic *nrfutil* on your computer (see below for specific instructions for ARM Linux)
3. Plug your Nordic nRF52840 dongle in your computer and press the *RESET* button (the one located close to the Nordic Semiconductor logo, it must be pushed *horizontally*).
4. Make sure a red LED blinks before continuing with next steps. If not retry step 3.
5. Execute the following command to upload the firmware into the dongle: ``nrfutil dfu usb-serial -pkg butterfly-fwupgrade.zip -p SERIAL_PORT -b 115200`` (replace SERIAL_PORT with your device serial port).

Building *nrfutil* for ARM Linux
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

On ARM Linux, we recommend using an old version of *nrfutil* that uses Python 2 (which is now deprecated). First, we
need to install a set of packages required to build Python:

.. code-block:: shell

    sudo apt install -y build-essential checkinstall libncursesw5-dev libssl-dev libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev libffi-dev

Then download the required Python 2 archive from the Python website and build it:

.. code-block:: shell

    wget https://www.python.org/ftp/python/2.7.18/Python-2.7.18.tgz
    tar -xvf Python-2.7.18.tgz
    cd Python-2.7.18
    ./configure --enable-optimizations
    make -j 10

.. important::

    There will be SSL errors on test 142 through 248, just ignore them.

Last, install this compiled version of Python and *nrfutil* using *pip*:

.. code-block:: shell

    sudo make install
    curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
    sudo python2.7 get-pip.py
    pip2.7 install nrfutil

To launch *nrfutil*:

.. code-block:: shell

    sudo -E python2.7 /home/user/.local/bin/nrfutil dfu usb-serial -pkg butterfly-fwupgrade.zip -p /dev/ttyACM0

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
    
    You must have the `STM32 Cube Programmer <https://www.st.com/en/development-tools/stm32cubeprog.html>`_ installed on your machine to flash this firmware.

1. Download the latest version of our WHAD-compatible firmware from the [corresponding repository](https://github.com/whad-team/stm32wlxx-firmware/releases/latest) named ``nucleo_wl55.hex``.
2. Launch STM32 Cube Programmer, connect the Nucleo STM32WL55 board to your computer and click *Connect*.
3. Go to the programming/upload tab, select the ``nucleo_wl55.hex`` file previously downloaded and upload it to the board.

.. _dev-esp32-wroom:

Espressif ESP32-WROOM
---------------------

ESP32-WROOM is a development board designed by Espressif that includes a 240 Mhz capable dual-core CPU and WiFi and
Bluetooth Low Energy capabilities. We developed a compatible firmware but it's still experimental. It's kinda working
but needs some adjustments to be really stable, so expect some disconnections.

Where to buy
^^^^^^^^^^^^

ESP32-WROOM are widely available, sold on Amazon or AliExpress for around $10 USD.

Install a WHAD-compatible firmware
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. warning::

    We are currently reworking the source code of the ESP32 NodeMCU to make it use our C/C++ library
    and the latest version of our WHAD protocol. It will be updated here as soon as possible.
