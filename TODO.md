# WHAD library
Python library allowing to interact with offensive security tools implementing the WHAD protocol.

### First release
- [ ] winject
- [ ] wplay / pcapDev
- [ ] parametre flush pour PCAPDevice + DLT
- [ ] wanalyzer
- [ ] definir les events generiques dans le protocole
- [ ] integration event à wfilter, wextract etc
- [ ] wzb-enddevice commandes shell
- [ ] Write documentation and tutorials
- [ ] Clean examples code
- [x] Create wuni-scan
- [x] Create wuni-keyboard
- [x] Create wuni-mouse
- [x] Rename ble-spawn to wble-spawn
- [x] Rename ble-connect to wble-connect
- [x] Rename ble-cli to wble-central
- [x] Rename protocol hub methods to follow snake case

### Repository structure
- [ ] Adding WHAD definitions repository as a submodule
- [ ] Adding flake8 and mypy
  - [ ] Fixing errors
  - [ ] Blacklisting protobuf library (automatically generated)
  - [ ] Integrating flake8 and mypy into tox and github-actions
- [ ] Defining entry points in configuration files (e.g., whadup)

### WHAD client unit tests
- [ ] Implementing unit tests for every software component
- [ ] Writing fixtures to mimick a WHAD-enabled device locally
- [ ] Improving tests coverage

### WHAD protocol definitions
- [ ] Adapting protocol definitions to allow distinction between Master to Slave and Slave to Master injections
- [ ] Refactoring capabilities to cover multiple protocols in a generic way (remove protocol-specific capabilities)
- [ ] Adding documentation of procedures

### WHAD library
- [ ] Implementing BLE hooking
- [ ] Implementing SM layer in BLE stack
- [ ] Implementing Peripheral role in BLE stack
  - [ ] Checking integration with existing connectors (e.g., Hijacker)
- [ ] Implementing BLE Jammer connector
- [ ] Implementing wireshark / PCAP export
- [ ] Implementing Zigbee connectors and stack
- [ ] Implementing ESB connectors and stack
  - [ ] Adding scapy layers
- [ ] Implementing Mosart connectors and stack
  - [ ] Adding scapy layers
- [ ] Implementing ANT protocol connectors and stack (ANT+ and ANT-FS)
  - [ ] Adding scapy layers
- [ ] Implementing Generic GFSK protocol connectors
- [ ] Improving examples structure, adding support of parameters
  - [ ] Moving client.py into examples, harmonizing the behaviour with other examples
