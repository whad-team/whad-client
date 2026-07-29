import os
import pytest

from scapy.layers.zigbee import ZigbeeAppDataPayload

from whad.zigbee.stack.aps import APSDataService
from whad.zigbee.stack.aps.database import APSIB
from whad.zigbee.stack.aps.constants import (
    APSDestinationAddressMode,
    APSFragmentationBlockType,
    APS_MAX_FRAME_SIZE,
)

HEADER_KWARGS = dict(
    delivery_mode=0,
    dst_endpoint=1,
    src_endpoint=1,
    profile=0x0104,
    cluster=0x0006,
    counter=42,
)


class FakeManager:
    """Minimal stand-in for a Dot15d4Manager, exposing only what
    APSDataService needs for these unit tests (self.database)."""
    def __init__(self):
        self.database = APSIB()


class FakeNWKDataService:
    def __init__(self):
        self.calls = []

    def data(self, apdu, **kwargs):
        self.calls.append((apdu, kwargs))
        return True


class FakeNWKLayer:
    def __init__(self):
        self._data_service = FakeNWKDataService()

    def get_service(self, name):
        assert name == "data"
        return self._data_service


class FakeManagerWithNWK(FakeManager):
    def __init__(self):
        super().__init__()
        self._nwk = FakeNWKLayer()

    def get_layer(self, name):
        assert name == 'nwk'
        return self._nwk


def split_into_fragments(asdu_bytes, header_kwargs, chunk_size=APS_MAX_FRAME_SIZE):
    """
    Mimics APSDataService.data()'s TX splitting logic, round-tripping each
    fragment through wire bytes to produce fixtures identical to what
    on_data_apdu() would hand to _reassemble_fragment() in real operation.
    """
    chunks = [
        asdu_bytes[offset:offset + chunk_size]
        for offset in range(0, len(asdu_bytes), chunk_size)
    ]
    fragments = []
    for block_number, chunk in enumerate(chunks):
        fragment_type = (
            APSFragmentationBlockType.FIRST_BLOCK if block_number == 0
            else APSFragmentationBlockType.MIDDLE_BLOCK
        )
        wire_block_number = len(chunks) if block_number == 0 else block_number
        fragment = ZigbeeAppDataPayload(
            frame_control=['extended_hdr'],
            aps_frametype=0,
            fragmentation=int(fragment_type),
            block_number=wire_block_number,
            **header_kwargs
        ) / chunk
        fragments.append(ZigbeeAppDataPayload(bytes(fragment)))
    return fragments


def test_reassembly_round_trip():
    asdu_bytes = os.urandom(3 * APS_MAX_FRAME_SIZE + 17)
    fragments = split_into_fragments(asdu_bytes, HEADER_KWARGS)

    service = APSDataService(FakeManager())
    result = None
    for fragment in fragments[:-1]:
        result = service._reassemble_fragment(fragment, source_address=0x1234)
        assert result is None

    result = service._reassemble_fragment(fragments[-1], source_address=0x1234)
    assert result is not None
    assert bytes(result.payload) == asdu_bytes


def test_reassembly_out_of_order():
    asdu_bytes = os.urandom(3 * APS_MAX_FRAME_SIZE + 17)
    fragments = split_into_fragments(asdu_bytes, HEADER_KWARGS)
    shuffled = [fragments[1], fragments[0], fragments[3], fragments[2]]

    service = APSDataService(FakeManager())
    result = None
    for fragment in shuffled[:-1]:
        result = service._reassemble_fragment(fragment, source_address=0x1234)
        assert result is None

    result = service._reassemble_fragment(shuffled[-1], source_address=0x1234)
    assert result is not None
    assert bytes(result.payload) == asdu_bytes


def test_reassembly_exact_multiple():
    """
    The first block's block_number announces the total block count, so
    completion is determined by having every position 0..total-1 filled in -
    not by the last fragment being shorter than APS_MAX_FRAME_SIZE. This
    must also work when the ASDU length is an exact multiple of
    APS_MAX_FRAME_SIZE, where the last fragment can't be distinguished from
    a middle fragment by length alone.
    """
    asdu_bytes = os.urandom(2 * APS_MAX_FRAME_SIZE)
    fragments = split_into_fragments(asdu_bytes, HEADER_KWARGS)

    service = APSDataService(FakeManager())
    result = None
    for fragment in fragments[:-1]:
        result = service._reassemble_fragment(fragment, source_address=0x1234)
        assert result is None

    result = service._reassemble_fragment(fragments[-1], source_address=0x1234)
    assert result is not None
    assert bytes(result.payload) == asdu_bytes


def test_data_splits_oversized_asdu_into_fragments():
    big_asdu = os.urandom(3 * APS_MAX_FRAME_SIZE + 10)
    manager = FakeManagerWithNWK()
    service = APSDataService(manager)

    result = service.data(
        big_asdu,
        destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
        destination_address=0x1234,
        destination_endpoint=1,
        profile_id=0x0104,
        cluster_id=0x0006,
        source_endpoint=1,
        fragmentation_permitted=True,
    )
    assert result is True

    calls = manager.get_layer('nwk').get_service('data').calls
    assert len(calls) == 4

    for index, (apdu, _kwargs) in enumerate(calls):
        expected_type = (
            APSFragmentationBlockType.FIRST_BLOCK if index == 0
            else APSFragmentationBlockType.MIDDLE_BLOCK
        )
        assert apdu.fragmentation == expected_type
        # The first block's block_number carries the total block count, not
        # its own (zero) position; subsequent blocks carry their position.
        expected_block_number = len(calls) if index == 0 else index
        assert apdu.block_number == expected_block_number
        assert 'extended_hdr' in apdu.frame_control

    reconstructed = b"".join(bytes(apdu.payload) for apdu, _ in calls)
    assert reconstructed == big_asdu


def test_data_does_not_fragment_small_asdu():
    small_asdu = os.urandom(APS_MAX_FRAME_SIZE - 1)
    manager = FakeManagerWithNWK()
    service = APSDataService(manager)

    result = service.data(
        small_asdu,
        destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
        destination_address=0x1234,
        destination_endpoint=1,
        profile_id=0x0104,
        cluster_id=0x0006,
        source_endpoint=1,
        fragmentation_permitted=True,
    )
    assert result is True

    calls = manager.get_layer('nwk').get_service('data').calls
    assert len(calls) == 1
    apdu, _kwargs = calls[0]
    assert 'extended_hdr' not in apdu.frame_control
