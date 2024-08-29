# WHAD: Wireless HAcking Devices

[![Tests](https://github.com/virtualabs/whad-client/actions/workflows/tests.yml/badge.svg)](https://github.com/virtualabs/whad-client/actions/workflows/tests.yml)

This framework provides a set of command-line tools to play with/hack/explore
wireless protocols and devices as well as a library to create powerful wireless
tools to use with hardware devices running a compatible firmware.

## Installation

Installation is pretty straightforward with ``pip``:

```
pip install whad
```

## Online documentation

Project documentation is [available on ReadTheDocs](https://whad.readthedocs.io/en/stable/).

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

