"""ESB Scapy layers parsing unit tests

This script provides different unit tests to ensure our ESB_Hdr scapy layer
works as expected.

The following tests are performed:
- 0x55 and 0xAA preamble are correctly extracted from an ESB frame
- no-ack bit is correctly extracted when set
- packet PID value is correctly parsed
- payload length is correctly extracted
- payload is correctly parsed as ESB_Payload_Hdr
- ESB ping request is correctly identified
"""
from whad.scapy.layers.esb import compute_crc, ESB_Hdr, ESB_Payload_Hdr, \
    ESB_Ping_Request

def build_esb_frame(address='01:02:03:04:05', payload=b'', no_ack=False, pid=0):
    """Build an ESB frame
    """
    preamble = 0xaa if bytes.fromhex(address[:2])[0] >= 0x80 else 0x55

    # Compute payload length
    payload_len = len(payload)&0x3F

    # Build packet config field
    pcf = (payload_len)<<3
    pcf |= (pid&0x3)<<1
    if no_ack:
        pcf |= 1

    # Build payload bytes
    carry = pcf&1
    out = []
    for x in payload:
        out.append((x>>1) | (carry << 7))
        carry = x&1
    out.append(carry<<7)

    # Compute CRC
    frame = bytes.fromhex(address.replace(':','')) + bytes([pcf>>1]) + bytes(out)
    crc = compute_crc(frame)

    # Append the packet CRC
    out[-1] |= crc[0]>>1
    out.append((crc[1]>>1) | (crc[0]&1)<<7)
    out.append((crc[1]&1)<<7)

    # Build the final frame
    return bytes([preamble]) + bytes.fromhex(address.replace(':','')) + bytes([pcf>>1]) + bytes(out)

def test_esb_frame_preamble_0x55():
    """Build an ESB frame with an address with its MSB set to 0
    and check ESB_Hdr parses it correctly
    """
    esb_frame = build_esb_frame("01:02:03:04:05", b"FOOBAR")
    packet = ESB_Hdr(esb_frame)
    assert packet.preamble == 0x55

def test_esb_frame_preamble_0xAA():
    """Build an ESB frame with an address with its MSB set to 1
    and check ESB_Hdr parses it correctly
    """
    esb_frame = build_esb_frame("81:02:03:04:05", b"FOOBAR")
    packet = ESB_Hdr(esb_frame)
    assert packet.preamble == 0xAA

def test_esb_frame_address():
    """Build an ESB frame with a specific address and check this address
    is correctly parsed by ESB_Hdr
    """
    esb_frame = build_esb_frame("01:02:03:04:05", b"FOOBAR")
    packet = ESB_Hdr(esb_frame)
    assert packet.address == "01:02:03:04:05"

def test_esb_frame_payload_size():
    """Build an ESB frame with a payload and check that ESB_Hdr correctly
    decodes the payload length
    """
    esb_frame = build_esb_frame("01:02:03:04:05", b"FOOBAR")
    packet = ESB_Hdr(esb_frame)
    assert packet.payload_length == 6

def test_esb_frame_payload():
    """Build an ESB frame with a payload and check that ESB_Hdr correctly
    decodes its payload
    """
    esb_frame = build_esb_frame("01:02:03:04:05", b"FOOBAR")
    packet = ESB_Hdr(esb_frame)
    assert packet.payload == ESB_Payload_Hdr(b"FOOBAR")

def test_esb_frame_noack():
    """Build an ESB frame with its *no ack* bit set and check if this bit
    is correctly parsed by ESB_Hdr
    """
    esb_frame = build_esb_frame("01:02:03:04:05", b"FOOBAR", no_ack=True)
    packet = ESB_Hdr(esb_frame)
    assert packet.no_ack == 1

def test_esb_frame_pid():
    """Build an ESB frame with its *pid* field set and check if this value
    is correctly parsed by ESB_Hdr
    """
    esb_frame = build_esb_frame("01:02:03:04:05", b"FOOBAR", pid=1)
    packet = ESB_Hdr(esb_frame)
    assert packet.pid == 1

def test_esb_ping_req():
    """Build an ESB ping packet and check if it is correctly interpreted by
    ESB_Hdr
    """
    esb_frame = build_esb_frame("01:02:03:04:05", b"\x0f\x0f\x0f\x0f")
    packet = ESB_Hdr(esb_frame)
    assert ESB_Ping_Request in packet

def test_esb_frame_crc():
    """Build an ESB frame and check CRC matches the expected one
    """
    frame = bytes.fromhex("0102030405192327a7a120a900")
    crc = compute_crc(frame)
    assert crc == b"\xa2\xb9"

def test_esb_frame_generation():
    esb_frame = build_esb_frame("01:02:03:04:05", b"\x0f\x0f\x0f\x0f")
    assert bytes(ESB_Hdr(esb_frame)) == esb_frame