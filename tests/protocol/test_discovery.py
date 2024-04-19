"""Protocol hub Discovery messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.device_pb2 import DeviceResetQuery, DeviceReadyResp
from whad.hub.discovery import Discovery, InfoQuery, InfoQueryResp, DomainInfoQuery, \
    DomainInfoQueryResp, SetSpeed, ResetQuery, DeviceReady


@pytest.fixture
def info_query():
    msg = Message()
    msg.discovery.info_query.proto_ver = 1
    return msg

@pytest.fixture
def info_resp():
    msg = Message()
    msg.discovery.info_resp.type = 1
    msg.discovery.info_resp.devid = b'devIddevId'
    msg.discovery.info_resp.proto_min_ver = 1
    msg.discovery.info_resp.max_speed = 9600
    msg.discovery.info_resp.fw_author = b'John Doe'
    msg.discovery.info_resp.fw_url = b'https://example.com'
    msg.discovery.info_resp.fw_version_major = 1
    msg.discovery.info_resp.fw_version_minor = 2
    msg.discovery.info_resp.fw_version_rev = 3
    msg.discovery.info_resp.capabilities.extend([
        0x01000001,
        0x02000001
    ])
    return msg

@pytest.fixture
def domain_query():
    msg = Message()
    msg.discovery.domain_query.domain = 1
    return msg

@pytest.fixture
def domain_query_resp():
    msg = Message()
    msg.discovery.domain_resp.domain = 2
    msg.discovery.domain_resp.supported_commands = 0x1122334455
    return msg

@pytest.fixture
def set_speed():
    msg = Message()
    msg.discovery.set_speed.speed = 115200
    return msg

@pytest.fixture
def reset_query():
    msg = Message()
    msg.discovery.reset_query.CopyFrom(DeviceResetQuery())
    return msg

@pytest.fixture
def ready_resp():
    msg = Message()
    msg.discovery.ready_resp.CopyFrom(DeviceReadyResp())
    return msg

class TestDiscoveryParsing(object):
    """Unit tests for discovery message parsing
    """

    def test_discovery_infoquery_parsing(self, info_query):
        """Test discovery info query message parsing.
        """
        parsed_obj = InfoQuery.parse(1, info_query)
        assert isinstance(parsed_obj, InfoQuery)

    def test_discovery_infoquery_resp_parsing(self, info_resp):
        """Test discovery info query response message parsing.
        """
        parsed_obj = InfoQueryResp.parse(1, info_resp)
        assert isinstance(parsed_obj, InfoQueryResp)
        assert parsed_obj.type == 1
        assert parsed_obj.device_id == b'devIddevId'
        assert parsed_obj.proto_min_ver == 1
        assert parsed_obj.max_speed == 9600
        assert parsed_obj.fw_author == b'John Doe'
        assert parsed_obj.fw_url == b'https://example.com'
        assert parsed_obj.fw_version_major == 1
        assert parsed_obj.fw_version_minor == 2
        assert parsed_obj.fw_version_rev == 3
        assert 0x01000001 in parsed_obj.capabilities
        assert 0x02000001 in parsed_obj.capabilities

    def test_discovery_domain_info_query_parsing(self, domain_query):
        """Test discovery domain info query parsing.
        """
        parsed_obj = DomainInfoQuery.parse(1, domain_query)
        assert isinstance(parsed_obj, DomainInfoQuery)
        assert parsed_obj.domain == 1

    def test_discovery_domain_info_resp_parsing(self, domain_query_resp):
        """Test discovery domain info response parsing.
        """
        parsed_obj = DomainInfoQueryResp.parse(1, domain_query_resp)
        assert isinstance(parsed_obj, DomainInfoQueryResp)
        parsed_obj.domain == 2
        parsed_obj.supported_commands == 0x1122334455

    def test_discovery_speed_update_parsing(self, set_speed):
        """Test discovery speed update message parsing.
        """
        parsed_obj = SetSpeed.parse(1, set_speed)
        assert isinstance(parsed_obj, SetSpeed)
        assert parsed_obj.speed == 115200

    def test_discovery_device_reset_parsing(self, reset_query):
        """Test discovery device reset message parsing.
        """
        parsed_obj = ResetQuery.parse(1, reset_query)
        assert isinstance(parsed_obj, ResetQuery)

    def test_discovery_device_ready_parsing(self, ready_resp):
        """Test discovery device ready message parsing.
        """
        parsed_obj = DeviceReady.parse(1, ready_resp)
        assert isinstance(parsed_obj, DeviceReady)

class TestDiscoveryCrafting(object):
    """Unit tests for device info query and response message crafting.
    """

    def test_discovery_info_query_crafting(self):
        """Test info query message crafting.
        """
        msg = InfoQuery(proto_ver = 42)
        assert msg.proto_ver == 42

    def test_discovery_info_resp_crafting(self):
        """Test info response message crafting.
        """
        msg = InfoQueryResp(type = 42, device_id = b'bidon', proto_min_ver = 3,
                            max_speed = 115200, fw_author = b'John Wick',
                            fw_url = b'https://linux.org', fw_version_major=2,
                            fw_version_minor=3, fw_version_rev=4,capabilities=[
                                0x11223344,
                                0x99887766
                            ])
        assert msg.type == 42
        assert msg.device_id == b'bidon'
        assert msg.proto_min_ver == 3
        assert msg.max_speed == 115200
        assert msg.fw_author == b'John Wick'
        assert msg.fw_url == b'https://linux.org'
        assert msg.fw_version_major == 2
        assert msg.fw_version_minor == 3
        assert msg.fw_version_rev == 4
        assert 0x11223344 in msg.capabilities
        assert 0x99887766 in msg.capabilities

    def test_discovery_domain_info_query_crafting(self):
        """Test discovery domain info query message crafting.
        """
        msg = DomainInfoQuery(domain=2)
        assert msg.domain == 2

    def test_discovery_domain_info_resp_crafting(self):
        """test discovery domain info response message crafting.
        """
        msg = DomainInfoQueryResp(domain=1, supported_commands=0x1122334455)
        assert msg.domain == 1
        assert msg.supported_commands == 0x1122334455

    def test_discovery_speed_update_crafting(self):
        """Test discovery speed update message crafting.
        """
        msg = SetSpeed(speed=9600)
        assert msg.speed == 9600


class TestDiscoveryFactory(object):
    """Unit tests for discovery factory methods.
    """

    def test_discovery_info_query_factory(self):
        """Test info query factory.
        """
        discovery = Discovery(1)
        msg = discovery.createInfoQuery(proto_ver=1)
        assert isinstance(msg, InfoQuery)

    def test_discovery_info_resp_factory(self):
        """Test info response factory.
        """
        discovery = Discovery(1)
        msg = discovery.createInfoResp(type = 42, device_id = b'bidon', proto_min_ver = 3,
                            max_speed = 115200, fw_author = b'John Wick',
                            fw_url = b'https://linux.org', fw_version_major=2,
                            fw_version_minor=3, fw_version_rev=4,capabilities=[
                                0x11223344,
                                0x99887766
                            ])
        assert isinstance(msg, InfoQueryResp)

    def test_discovery_domain_query_factory(self):
        """Test discovery domain query factory.
        """
        discovery = Discovery(1)
        msg = discovery.createDomainQuery(domain=42)
        assert isinstance(msg, DomainInfoQuery)

    def test_discovery_domain_resp_factory(self):
        """Test discovery domain response factory.
        """
        discovery = Discovery(1)
        msg = discovery.createDomainResp(domain=42, supported_commands=0x112233445566)
        assert isinstance(msg, DomainInfoQueryResp)

    def test_discovery_set_speed_factory(self):
        """Test discovery speed update factory.
        """
        discovery = Discovery(1)
        msg = discovery.createSetSpeed(speed=9600)
        assert isinstance(msg, SetSpeed)

    def test_discovery_reset_query_factory(self):
        """Test discovery reset query factory.
        """
        discovery = Discovery(1)
        msg = discovery.createResetQuery()
        assert isinstance(msg, ResetQuery)

    def test_discovery_device_ready_factory(self):
        """Test discovery ready resp factory.
        """
        discovery = Discovery(1)
        msg = discovery.createDeviceReady()
        assert isinstance(msg, DeviceReady)

class TestDiscoveryDispatch(object):
    """Unit tests for discovery message dispatch.
    """

    def test_discovery_infoquery_parsing(self, info_query):
        """Test discovery info query message parsing.
        """
        parsed_obj = Discovery.parse(1, info_query)
        assert isinstance(parsed_obj, InfoQuery)

    def test_discovery_infoquery_resp_parsing(self, info_resp):
        """Test discovery info query response message parsing.
        """
        parsed_obj = Discovery.parse(1, info_resp)
        assert isinstance(parsed_obj, InfoQueryResp)

    def test_discovery_domain_info_query_parsing(self, domain_query):
        """Test discovery domain info query parsing.
        """
        parsed_obj = Discovery.parse(1, domain_query)
        assert isinstance(parsed_obj, DomainInfoQuery)

    def test_discovery_domain_info_resp_parsing(self, domain_query_resp):
        """Test discovery domain info response parsing.
        """
        parsed_obj = Discovery.parse(1, domain_query_resp)
        assert isinstance(parsed_obj, DomainInfoQueryResp)

    def test_discovery_speed_update_parsing(self, set_speed):
        """Test discovery speed update message parsing.
        """
        parsed_obj = Discovery.parse(1, set_speed)
        assert isinstance(parsed_obj, SetSpeed)

    def test_discovery_device_reset_parsing(self, reset_query):
        """Test discovery device reset message parsing.
        """
        parsed_obj = Discovery.parse(1, reset_query)
        assert isinstance(parsed_obj, ResetQuery)

    def test_discovery_device_ready_parsing(self, ready_resp):
        """Test discovery device ready message parsing.
        """
        parsed_obj = Discovery.parse(1, ready_resp)
        assert isinstance(parsed_obj, DeviceReady)
