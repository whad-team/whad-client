"""Protocol hub PHY messages unit tests
"""
from whad.protocol.whad_pb2 import Message
from whad.hub.phy import PhyDomain, SetAskMod, SetBpskMod, SetFskMod, SetGfskMod, SetLoRaMod, \
    SetMskMod, SetQpskMod, Set4FskMod, GetSupportedFreqs, SetFreq, SupportedFreqRanges, SniffMode, \
    JamMode, MonitorMode, Start, Stop, SetDatarate, SetEndianness, SetPacketSize, SetSyncWord, SetTxPower, \
    SendPacket, SendRawPacket, PacketReceived, RawPacketReceived, SchedulePacket, SchedulePacketResponse, \
    ScheduledPacketSent

from test_mod import set_ask_mod, set_bpsk_mod, set_fsk_mod, set_gfsk_mod, set_lora_mod, \
    set_msk_mod, set_qpsk_mod, set_4fsk_mod
from test_freq import set_freq, supp_freq_ranges, get_supp_freqs
from test_mode import set_sniff_mode, set_jam_mode, set_monitor_mode, start, stop
from test_packet import set_datarate, set_endianness, set_packet_size, set_sync_word, set_txpower, \
    send_packet, send_raw_packet, raw_packet_received, packet_received
from test_schedule import schedule_packet_send, schedule_packet_sent, schedule_packet_resp

class TestPhyParsing(object):
    """Test parsing of PHY messages.
    """

    def test_ask_mod_parsing(self, set_ask_mod):
        """Check parsing of SetAskModCmd message.
        """
        msg = PhyDomain.parse(1, set_ask_mod)
        assert isinstance(msg, SetAskMod)

    def test_bpsk_mod_parsing(self, set_bpsk_mod):
        """Check parsing of SetBpskModCmd message.
        """
        msg = PhyDomain.parse(1, set_bpsk_mod)
        assert isinstance(msg, SetBpskMod)

    def test_fsk_mod_parsing(self, set_fsk_mod):
        """Check parsing of SetFskModCmd message.
        """
        msg = PhyDomain.parse(1, set_fsk_mod)
        assert isinstance(msg, SetFskMod)

    def test_gfsk_mod_parsing(self, set_gfsk_mod):
        """Check parsing of SetGfskMod message.
        """
        msg = PhyDomain.parse(1, set_gfsk_mod)
        assert isinstance(msg, SetGfskMod)

    def test_lora_mod_parsing(self, set_lora_mod):
        """Check parsing of SetLoRaMod message.
        """
        msg = PhyDomain.parse(1, set_lora_mod)
        assert isinstance(msg, SetLoRaMod)

    def test_msk_mod_parsing(self, set_msk_mod):
        """Check parsing of SetMskMod message.
        """
        msg = PhyDomain.parse(1, set_msk_mod)
        assert isinstance(msg, SetMskMod)

    def test_qpsk_mod_parsing(self, set_qpsk_mod):
        """Check parsing of SetQpskMod message.
        """
        msg = PhyDomain.parse(1, set_qpsk_mod)
        assert isinstance(msg, SetQpskMod)

    def test_4fsk_mod_parsing(self, set_4fsk_mod):
        """Check parsing of Set4FskMod message.
        """
        msg = PhyDomain.parse(1, set_4fsk_mod)
        assert isinstance(msg, Set4FskMod)

    def test_set_freq_parsing(self, set_freq):
        """Check parsing of SetFreq message.
        """
        msg = PhyDomain.parse(1, set_freq)
        assert isinstance(msg, SetFreq)

    def test_get_supp_freqs_parsing(self, get_supp_freqs):
        """Check parsing of GetSupportedFreqs message.
        """
        msg = PhyDomain.parse(1, get_supp_freqs)
        assert isinstance(msg, GetSupportedFreqs)

    def test_supp_freqs_parsing(self, supp_freq_ranges):
        """Check parsing of SupportedFreqRanges message.
        """
        msg = PhyDomain.parse(1, supp_freq_ranges)
        assert isinstance(msg, SupportedFreqRanges)

    def test_sniff_mode_parsing(self, set_sniff_mode):
        """Check parsing of SniffMode message.
        """
        msg = PhyDomain.parse(1, set_sniff_mode)
        assert isinstance(msg, SniffMode)

    def test_jam_mode_parsing(self, set_jam_mode):
        """Check parsing of JamMode message.
        """
        msg = PhyDomain.parse(1, set_jam_mode)
        assert isinstance(msg, JamMode)

    def test_monitor_mode_parsing(self, set_monitor_mode):
        """Check parsing of MonitorMode message.
        """
        msg = PhyDomain.parse(1, set_monitor_mode)
        assert isinstance(msg, MonitorMode)

    def test_start_parsing(self, start):
        """Check parsing of Start message.
        """
        msg = PhyDomain.parse(1, start)
        assert isinstance(msg, Start)

    def test_stop_parsing(self, stop):
        """Check parsing of Stop message.
        """
        msg = PhyDomain.parse(1, stop)
        assert isinstance(msg, Stop)

    def test_set_datarate_parsing(self, set_datarate):
        """Check parsing of SetDatarate message.
        """
        msg = PhyDomain.parse(1, set_datarate)
        assert isinstance(msg, SetDatarate)

    def test_set_packet_size_parsing(self, set_packet_size):
        """Check parsing of SetPacketSize message.
        """
        msg = PhyDomain.parse(1, set_packet_size)
        assert isinstance(msg, SetPacketSize)

    def test_set_syncword_parsing(self, set_sync_word):
        """Check parsing of SetSyncWord message.
        """
        msg = PhyDomain.parse(1, set_sync_word)
        assert isinstance(msg, SetSyncWord)

    def test_set_txpower_parsing(self, set_txpower):
        """Check parsing of SetTxPower message.
        """
        msg = PhyDomain.parse(1, set_txpower)
        assert isinstance(msg, SetTxPower)

    def test_set_endianness_parsing(self, set_endianness):
        """Check parsing of SetEndianness message.
        """
        msg = PhyDomain.parse(1, set_endianness)
        assert isinstance(msg, SetEndianness)

    def test_send_pkt_parsing(self, send_packet):
        """Check parsing of SendPacket message.
        """
        msg = PhyDomain.parse(1, send_packet)
        assert isinstance(msg, SendPacket)

    def test_send_raw_pkt_parsing(self, send_raw_packet):
        """Check parsing of SendRawPacket message.
        """
        msg = PhyDomain.parse(1, send_raw_packet)
        assert isinstance(msg, SendRawPacket)

    def test_pkt_recv_parsing(self, packet_received):
        """Check parsing of PacketReceived message.
        """
        msg = PhyDomain.parse(1, packet_received)
        assert isinstance(msg, PacketReceived)

    def test_raw_pkt_recv_parsing(self, raw_packet_received):
        """Check parsing of RawPacketReceived message.
        """
        msg = PhyDomain.parse(1, raw_packet_received)
        assert isinstance(msg, RawPacketReceived)

    def test_sched_send_parsing(self, schedule_packet_send):
        """Check parsing of SchedulePacket message.
        """
        msg = PhyDomain.parse(1, schedule_packet_send)
        assert isinstance(msg, SchedulePacket)

    def test_sched_send_rsp_parsing(self, schedule_packet_resp):
        """Check parsing of SchedulePacketResponse message.
        """
        msg = PhyDomain.parse(1, schedule_packet_resp)
        assert isinstance(msg, SchedulePacketResponse)

    def test_sched_pkt_sent_parsing(self, schedule_packet_sent):
        """Check parsing of ScheduledPacketSent message.
        """
        msg = PhyDomain.parse(1, schedule_packet_sent)
        assert isinstance(msg, ScheduledPacketSent)
