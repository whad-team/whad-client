Installation
=============

Installing WHAD from pip
-------------------------

Installing WHAD is straightforward with ``pip``:

.. code-block:: text

    pip install whad


Installing WHAD from Github repository
----------------------------------------

Another solution is to get the source from github directly:

.. code-block:: text

    $ git clone https://github.com/whad-team/whad-client.git
    $ cd whad-client
    $ pip install .

Installing rules for WHAD-compatible devices
---------------------------------------------

By default, interacting with most WHAD-compatible devices require root permissions.

To allow a normal user to interact with them, a simple tool named ``winstall`` is included in whad.
It can automatically install rules & configure permissions for the supported devices.

To install the rules for all devices, just run the following command:

.. code-block:: text

    $ winstall --rules all

A prompt will ask your password to elevate your privileges, then rules and permissions will be automatically configured.
On some system, it may be necessary to logout in order to apply changes.

If you prefer to install rules for a specific device, replace 'all' by the device you want to configure:

.. code-block:: text

    # Install rules for HCI devices
    $ winstall --rules hci

    # Install rules for ButteRFly device (nRF52840 dongle - pca10059 or Makerdiary MDK nrf52 dongle)
    $ winstall --rules butterfly

    # Install rules for nodeMCU ESP-32
    $ winstall --rules esp

    # Install rules for nucleo STM32-WL55
    $ winstall --rules nucleowl55

    # Install rules for LoRa e5 mini dongle
    $ winstall --rules lorae5mini

    # Install rules for Ubertooth One
    $ winstall --rules ubertooth

    # Install rules for Yard Stick One
    $ winstall --rules yardstickone

    # Install rules for RFStorm device (CrazyRadio PA / Logitech Unifying dongle)
    $ winstall --rules rfstorm

    # Install rules for APIMote device
    $ winstall --rules apimote

    # Install rules for RZUSBStick
    $ winstall --rules rzusbstickrfstorm


Flashing firmware on WHAD-compatible devices
---------------------------------------------

``winstall`` tool also allows to flash the latest available firmware on various WHAD-enabled devices.

Plug your device on your computer, and check if it is correctly detected using ``--list`` option:

.. code-block:: text

    $ winstall --list
    [!] Detected devices:

    - Ubertooth One:  0
      Command (install rules): winstall --rules ubertooth
      Command (flash firmware): winstall --flash ubertooth --port 0

    - Espressif ESP-32 board:  /dev/ttyUSB0
    Command (install rules): winstall --rules esp
    Command (flash firmware): winstall --flash esp --port /dev/ttyUSB0

    - HCI device:  hci0
    Command (install rules): winstall --rules hci

Then, flash the latest device using the ``--flash`` option (you can provide a specific port using ``--port``):

.. code-block:: text

    $ winstall --flash ubertooth
    [!] This tool must run as root, let's elevate your privileges !
    [...]
    [!] Flashing ubertooth device ...
    Latest ubertooth release: 2020-12-R1
    [!] Running command: tar -xf /tmp/ubertooth-2020-12-R1.tar.xz
    [!] Running command: ubertooth-dfu -d bluetooth_rxtx.dfu -r
    Flashing successful for device 'ubertooth'.

Once correctly flashed, you should be able to see the available devices using ``wup`` / ``whadup``:

.. code-block:: text

    $ whadup
    [i] Available devices
    - ubertooth0
      Type: UbertoothDevice
      Index: 0
      Identifier: 16b00016c61435aeaec24253811e00f5

    - hci0
      Type: HCIDevice
      Index: 0
      Identifier: hci0

    - uart0
      Type: UartDevice
      Index: 0
      Identifier: /dev/ttyUSB0
