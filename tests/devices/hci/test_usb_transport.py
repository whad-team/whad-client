"""Offline tests for the Realtek USB HCI transport."""

from types import SimpleNamespace

import pytest

from whad.device.hci.realtek import RealtekFirmwareError
from whad.device.hci.usb_transport import _PacketSplitter, RealtekUSBTransport


def test_event_splitter_handles_partial_and_coalesced_usb_transfers():
    splitter = _PacketSplitter(0x04, 2, 1)
    assert splitter.feed(b"\x0e\x02\x01") == []
    assert splitter.feed(b"\x02\x0f\x01") == [b"\x04\x0e\x02\x01\x02"]
    assert splitter.feed(b"\x03") == [b"\x04\x0f\x01\x03"]


def test_acl_splitter_uses_little_endian_payload_length():
    splitter = _PacketSplitter(0x02, 4, 2)
    assert splitter.feed(b"\x01\x00\x02\x00\xaa") == []
    assert splitter.feed(b"\xbb") == [b"\x02\x01\x00\x02\x00\xaa\xbb"]


def test_c_already_patched_can_use_hci_without_firmware_download(monkeypatch):
    transport = RealtekUSBTransport.__new__(RealtekUSBTransport)
    monkeypatch.setattr(
        transport, "command", lambda command: SimpleNamespace(
            status=0, company_identifier=0x005D, hci_version=0x0D,
            hci_subversion=0x7A43, lmp_subversion=0xEEE3,
        ),
    )

    assert transport.load_firmware_if_needed() == 51


def test_unknown_realtek_usb_firmware_state_is_rejected(monkeypatch):
    transport = RealtekUSBTransport.__new__(RealtekUSBTransport)
    monkeypatch.setattr(
        transport, "command", lambda command: SimpleNamespace(
            status=0, company_identifier=0x005D, hci_version=0x0A,
            hci_subversion=0x1111, lmp_subversion=0x2222,
        ),
    )

    with pytest.raises(RealtekFirmwareError, match="unsupported firmware state"):
        transport.load_firmware_if_needed()
