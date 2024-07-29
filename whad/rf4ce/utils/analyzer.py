from whad.common.analyzer import TrafficAnalyzer
from whad.scapy.layers.rf4ce import RC_COMMAND_CODES, RF4CE_Vendor_MSO_Audio_Start_Request, \
    RF4CE_Vendor_ZRC_User_Control_Pressed, RF4CE_Vendor_MSO_User_Control_Pressed, \
    RF4CE_Vendor_MSO_Audio_Data_Notify, RF4CE_Vendor_MSO_Audio_Stop_Request, \
    RF4CE_Vendor_MSO_Audio
from whad.rf4ce.utils.adpcm import ADPCM
from whad.rf4ce.crypto import RF4CEKeyDerivation
import os, tempfile

class RF4CEAudio(TrafficAnalyzer):
    def __init__(self):
        super().__init__()

    @property
    def output(self):
        return {
            "raw_audio" :self.raw_audio
        }

    def reset(self):
        super().reset()
        self.audio_filename = os.path.join(tempfile.mkdtemp()+ '.wav')
        self.adpcm = ADPCM(live_play=False, output_filename=self.audio_filename)
        self.raw_audio = None

    def process_packet(self, packet):
        if RF4CE_Vendor_MSO_Audio_Start_Request in packet:
            self.trigger()
            self.adpcm.process_packet(packet)
            self.mark_packet(packet)

        elif RF4CE_Vendor_MSO_Audio_Data_Notify in packet:
            self.adpcm.process_packet(packet)
            self.mark_packet(packet)

        elif RF4CE_Vendor_MSO_Audio_Stop_Request in packet or (RF4CE_Vendor_MSO_Audio in packet and packet.audio_cmd_id == 2):
            self.adpcm.process_packet(packet)
            self.mark_packet(packet)
            with open(self.audio_filename, "rb") as f:
                self.raw_audio = f.read()
            os.unlink(self.audio_filename)
            self.complete()

class RF4CEKeystroke(TrafficAnalyzer):

    @property
    def output(self):
        return {
            "key" :self.key
        }

    def process_packet(self, packet):
        code = None
        if RF4CE_Vendor_ZRC_User_Control_Pressed in packet or RF4CE_Vendor_MSO_User_Control_Pressed in packet:
            self.trigger()
            self.mark_packet(packet)
            code = packet.code


        if code is not None:
            try:
                key = RC_COMMAND_CODES[code]

                if key != self.key:
                    self.key = key
                    if len(self.key) > 1:
                        self.key = " [{}] ".format(self.key)
                    self.complete()
            except KeyError:
                self.reset()

    def reset(self):
        super().reset()
        self.key = None

analyzers = {
    "key_cracking" : RF4CEKeyDerivation,
    "audio" : RF4CEAudio,
    "keystroke" : RF4CEKeystroke
}
