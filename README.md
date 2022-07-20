# WHAD library
[![Tests](https://github.com/virtualabs/whad-client/actions/workflows/tests.yml/badge.svg)](https://github.com/virtualabs/whad-client/actions/workflows/tests.yml)

This repository contains a python library allowing to easily interact with offensive hardware tools implementing the WHAD (Wireless HAcking Devices).

## Repository structure

The project is structured as follow:

```markdown
.
├── examples                          # directory of examples describing basic use cases
│   ├── ble_advertisements_sniffer.py
│   ├── ble_both_hijacker.py
│   ├── ble_connection_sniffer.py
│   ├── ble_injector.py
│   ├── ble_master_hijacker.py
│   └── ble_slave_hijacker.py
├── TODO.md                           # TODO file
├── LICENSE                           # license file
├── pyproject.toml                    # configuration file
├── README.md                         # the README file you are currently reading
├── requirements_dev.txt              # file listing dependencies needed to run the tests
├── requirements.txt                  # file listing dependencies needed to run WHAD
├── setup.cfg                         # configuration file
├── setup.py                          # installation script
├── tests                             # directory of unit tests
├── tox.ini                           # TOX configuration file
├── whad                              # source code of WHAD package
└── whadup.py                         # utility allowing to display WHAD capabilities implemented by a specific device
```

## Required dependencies

The following dependencies are needed to use this package:
- protobuf (>=4.21.2)
- scapy (>=2.4.55)
- elementpath (>=2.4.0)
- pyserial (>=3.5.0)

If you want to run the tests, you also need to install the following dependencies:
- tox (>=3.9.0)
- pytest (>=6.2.5)
- pytest-cov (>=2.12.1)

## Running unit tests

You can run unit tests locally for the default python version using:
```
pytest
```

You can run unit tests for every supported python version using:
```
tox
```

(Obviously, you need to install python interpreter from 3.6 to 3.10 included to run tox).
The tests are automatically run by github actions when something is pushed to main branch or when a pull request is merged.

## Installing the package

You can install the package easily using:
```
pip install .
```

Then, connect a compatible WHAD-enabled device and run whadup utility.
```
python3 whadup.py /dev/ttyACM0
```

You should get an output similar to the following one:
```
[i] Connecting to device ...
[i] Discovering domains ...
[i] Domains discovered.

This device supports Bluetooth LE:
 - can sniff data
 - can inject packets
 - can hijack connections
 - can act as a master
 - can act as a slave

 List of supported commands:
  - SniffAdv: can sniff advertising PDUs
  - SniffConnReq: can sniff a new connection
  - CentralMode: can act as a Central device
  - SendPDU: can send a raw PDU
  - PeripharlMode: can act as a peripheral
  - Start: can start depending on the current mode
  - Stop: can stop depending on the current mode
  - HijackMaster: can hijack the Master role in an active connection
  - HijackSlave: can hijack the Slave role in an active connection

This device supports ZigBee:
 - can sniff data
 - can inject packets
 - can jam connections

 List of supported commands:
  - Sniff: can sniff Zigbee packets
  - Jam: can jam Zigbee packets
  - Send: can transmit Zigbee packets
  - Start: can start depending on the current mode
  - Stop: can stop depending on the current mode
  - ManInTheMiddle: can perform a Man-in-the-Middle attack

[i] Device ID: c2:b8:c2:aa:c2:b4:35:09:4f:7e:c3:b5:c3:aa:2a:31:16:66:2f:35:67
```

## Running basic examples

### Sniffing Bluetooth Low Energy advertisements
If your device supports BLE advertisements sniffing, you can sniff advertisements by running the following command:
```
python3 examples/ble_advertisements_sniffer.py /dev/ttyACM0
```

### Sniffing Bluetooth Low Energy connections
If your device supports BLE connections sniffing, you can sniff connections by running the following command:
```
python3 examples/ble_connection_sniffer.py /dev/ttyACM0
```
