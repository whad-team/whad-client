import os
import pytest

from scapy.layers.zigbee import ZigbeeAppDataPayload

from whad.exceptions import RequiredImplementation
from whad.zigbee.stack.aps import APSDataService
from whad.zigbee.stack.aps.database import APSIB
from whad.zigbee.stack.aps.constants import (
    APSDestinationAddressMode,
    APS_MAX_FRAME_SIZE,
    APS_MAX_FRAME_RETRIES,
)

DATA_KWARGS = dict(
    destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
    destination_address=0x1234,
    destination_endpoint=1,
    profile_id=0x0104,
    cluster_id=0x0006,
    source_endpoint=1,
)


class FakeManager:
    """Minimal stand-in for a Dot15d4Manager, exposing only what
    APSDataService needs for these unit tests (self.database)."""
    def __init__(self):
        self.database = APSIB()


class FakeNWKDataService:
    def __init__(self, on_send=None):
        self.calls = []
        # Optional callable(apdu, kwargs) -> bool, invoked synchronously
        # from data(), standing in for whatever the real NWK/MAC layers
        # would do (e.g. enqueue a matching ack before returning).
        self.on_send = on_send

    def data(self, apdu, **kwargs):
        self.calls.append((apdu, kwargs))
        if self.on_send is not None:
            return self.on_send(apdu, kwargs)
        return True


class FakeNWKLayer:
    def __init__(self, on_send=None):
        self._data_service = FakeNWKDataService(on_send=on_send)

    def get_service(self, name):
        assert name == "data"
        return self._data_service


class FakeManagerWithNWK(FakeManager):
    def __init__(self, on_send=None):
        super().__init__()
        self._nwk = FakeNWKLayer(on_send=on_send)

    def get_layer(self, name):
        assert name == 'nwk'
        return self._nwk


def make_ack(apdu):
    """Builds a minimal APS ack matching ``apdu``'s counter, as a real peer's
    indicate_data() would produce it."""
    return ZigbeeAppDataPayload(aps_frametype=2, counter=apdu.counter)


def test_data_sets_ack_req_flag():
    def on_send(apdu, kwargs):
        service.add_packet_to_queue(make_ack(apdu))
        return True

    manager = FakeManagerWithNWK(on_send=on_send)
    service = APSDataService(manager)

    assert service.data(b"payload", acknowledged_transmission=True, **DATA_KWARGS) is True
    apdu, _ = manager.get_layer('nwk').get_service('data').calls[0]
    assert 'ack_req' in apdu.frame_control

    manager = FakeManagerWithNWK()
    service = APSDataService(manager)
    assert service.data(b"payload", acknowledged_transmission=False, **DATA_KWARGS) is True
    apdu, _ = manager.get_layer('nwk').get_service('data').calls[0]
    assert 'ack_req' not in apdu.frame_control


def test_data_ack_success_first_attempt():
    def on_send(apdu, kwargs):
        service.add_packet_to_queue(make_ack(apdu))
        return True

    manager = FakeManagerWithNWK(on_send=on_send)
    service = APSDataService(manager)

    result = service.data(b"payload", acknowledged_transmission=True, **DATA_KWARGS)
    assert result is True
    assert len(manager.get_layer('nwk').get_service('data').calls) == 1


def test_data_ack_success_after_retry():
    attempts = {"count": 0}

    def on_send(apdu, kwargs):
        attempts["count"] += 1
        if attempts["count"] >= 2:
            service.add_packet_to_queue(make_ack(apdu))
        return True

    manager = FakeManagerWithNWK(on_send=on_send)
    service = APSDataService(manager)
    service.database.set("apsAckWaitDuration", 0.05)

    result = service.data(b"payload", acknowledged_transmission=True, **DATA_KWARGS)
    assert result is True
    assert len(manager.get_layer('nwk').get_service('data').calls) == 2


def test_data_ack_timeout_exhausts_retries():
    manager = FakeManagerWithNWK(on_send=lambda apdu, kwargs: True)
    service = APSDataService(manager)
    service.database.set("apsAckWaitDuration", 0.02)

    result = service.data(b"payload", acknowledged_transmission=True, **DATA_KWARGS)
    assert result is False
    assert len(manager.get_layer('nwk').get_service('data').calls) == APS_MAX_FRAME_RETRIES


def test_data_ack_nwk_send_failure_exhausts_retries():
    manager = FakeManagerWithNWK(on_send=lambda apdu, kwargs: False)
    service = APSDataService(manager)

    result = service.data(b"payload", acknowledged_transmission=True, **DATA_KWARGS)
    assert result is False
    assert len(manager.get_layer('nwk').get_service('data').calls) == APS_MAX_FRAME_RETRIES


def test_data_fragmented_ack_raises_required_implementation():
    manager = FakeManagerWithNWK()
    service = APSDataService(manager)
    big_asdu = os.urandom(3 * APS_MAX_FRAME_SIZE + 10)

    with pytest.raises(RequiredImplementation):
        service.data(
            big_asdu,
            acknowledged_transmission=True,
            fragmentation_permitted=True,
            **DATA_KWARGS
        )
    assert len(manager.get_layer('nwk').get_service('data').calls) == 0


def test_data_ack_with_fragmentation_permitted_but_small_payload_still_works():
    """fragmentation_permitted=True must not itself trigger the fragmented-ack
    guard when the payload doesn't actually need to be split."""
    def on_send(apdu, kwargs):
        service.add_packet_to_queue(make_ack(apdu))
        return True

    manager = FakeManagerWithNWK(on_send=on_send)
    service = APSDataService(manager)

    result = service.data(
        b"small payload",
        acknowledged_transmission=True,
        fragmentation_permitted=True,
        **DATA_KWARGS
    )
    assert result is True
    assert len(manager.get_layer('nwk').get_service('data').calls) == 1
