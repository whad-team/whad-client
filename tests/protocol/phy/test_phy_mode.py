"""Protocol hub PHY mode messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.phy.phy_pb2 import StartCmd, StopCmd, MonitorCmd, JammingMode
from whad.hub.phy import PhyDomain, SniffMode, JamMode, MonitorMode, Start, Stop, \
    Jammed, MonitoringReport

@pytest.fixture
def set_sniff_mode():
    """Create a SniffCmd protobuf message
    """
    msg = Message()
    msg.phy.sniff.iq_stream = False
    return msg

@pytest.fixture
def set_jam_mode():
    """Create a JamCmd protobuf message
    """
    msg = Message()
    msg.phy.jam.mode = JammingMode.CONTINUOUS
    return msg

@pytest.fixture
def jammed():
    """Create a Jammed protobuf message
    """
    msg = Message()
    msg.phy.jammed.timestamp = 12349876
    return msg

@pytest.fixture
def set_monitor_mode():
    """Create a MonitorCmd protobuf message
    """
    msg = Message()
    msg.phy.monitor.CopyFrom(MonitorCmd())
    return msg

@pytest.fixture
def monitor_report():
    """Create a MonitoringReport protobuf message
    """
    msg = Message()
    msg.phy.monitor_report.timestamp = 1234
    msg.phy.monitor_report.report.append(12)
    msg.phy.monitor_report.report.append(34)
    return msg

@pytest.fixture
def start():
    """Create a StartCmd protobuf message
    """
    msg = Message()
    msg.phy.start.CopyFrom(StartCmd())
    return msg

@pytest.fixture
def stop():
    """Create a StopCmd protobuf message
    """
    msg = Message()
    msg.phy.stop.CopyFrom(StopCmd())
    return msg


class TestModes(object):
    """Test parsing of PHY modes messages.
    """

    def test_sniff_mode_parsing(self, set_sniff_mode):
        """Check parsing of SniffCmd
        """
        parsed_obj = SniffMode.parse(1, set_sniff_mode)
        assert isinstance(parsed_obj, SniffMode)
        assert parsed_obj.iq_stream == False

    def test_jam_mode_parsing(self, set_jam_mode):
        """Check parsing of JamCmd
        """
        parsed_obj = JamMode.parse(1, set_jam_mode)
        assert isinstance(parsed_obj, JamMode)
        assert parsed_obj.mode == JammingMode.CONTINUOUS

    def test_jammed_parsing(self, jammed):
        """Check parsing of JammedCmd
        """
        parsed_obj = Jammed.parse(1, jammed)
        assert isinstance(parsed_obj, Jammed)
        assert parsed_obj.timestamp == 12349876

    def test_monitor_mode_parsing(self, set_monitor_mode):
        """Check parsing of MonitorCmd
        """
        parsed_obj = MonitorMode.parse(1, set_monitor_mode)
        assert isinstance(parsed_obj, MonitorMode)

    def test_monitor_report_parsing(self, monitor_report):
        """Check parsing of MonitoringReportCmd
        """
        parsed_obj = MonitoringReport.parse(1, monitor_report)
        assert isinstance(parsed_obj, MonitoringReport)
        assert parsed_obj.timestamp == 1234
        assert len(parsed_obj.reports) == 2

    def test_start_parsing(self, start):
        """Check parsing of StartCmd
        """
        parsed_obj = Start.parse(1, start)
        assert isinstance(parsed_obj, Start)

    def test_stop_parsing(self, stop):
        """Check parsing of StopCmd
        """
        parsed_obj = Stop.parse(1, stop)
        assert isinstance(parsed_obj, Stop)