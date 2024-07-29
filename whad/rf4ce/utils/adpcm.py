'''
ADPCM codec implementation.

*All* credits for this code goes to https://github.com/ShowerXu/python-adpcm/.
'''
from whad.scapy.layers.rf4ce import RF4CE_Vendor_MSO_Audio_Start_Request, \
		RF4CE_Vendor_MSO_Audio_Data_Notify, RF4CE_Vendor_MSO_Audio_Stop_Request, \
		RF4CE_Vendor_MSO_Audio
from struct import pack, unpack
import wave

resolution = 16

# Build geometric lookup table with base as 1.1, as used in IMA and OKI
STEP_TABLE = [7]
while STEP_TABLE[-1] <= (2**resolution) / 2:
		STEP_TABLE.append(1.1 * STEP_TABLE[-1])

# Trim last one which will be outside the valid range
STEP_TABLE = [int(round(x)) for x in STEP_TABLE[:-1]]

# Index table from IMA and OKI
INDEX_TABLE = [
		-1, -1, -1, -1, 2, 4, 6, 8
]

class ByteAdpcmEncoder:
	def __init__(self, start):
		self.predicted = start
		self.start_index = None
		self.index = None

	def _find_best_index(self, diff):
		best_step = 0
		best_step_diff = abs(STEP_TABLE[0] - diff)

		for i in range(1, len(STEP_TABLE)):
			cur_step_diff = abs(STEP_TABLE[i] - diff)
			if cur_step_diff < best_step_diff:
				best_step = i
				best_step_diff = cur_step_diff

		return best_step

	def encode(self, value):
		delta = value - self.predicted
		if delta < 0:
			isNeg = True
			delta = -delta
		else:
			isNeg = False

		if self.start_index is None:
			self.start_index = self.index = self._find_best_index(delta)

		index = self.index
		predicted = self.predicted
		step = STEP_TABLE[index]

		predicted_delta = 0
		encoded = 0

		if delta >= step:
			delta -= step
		predicted_delta += step
		encoded |= 0x4

		step = step >> 1
		if delta >= step:
			delta -= step
		predicted_delta += step
		encoded |= 0x2

		step >>= 1
		if delta >= step:
			predicted_delta += step
		encoded |= 0x1

		# Is this needed?
		step >>= 1
		predicted_delta += step

		index += INDEX_TABLE[encoded]
		if index < 0:
			index = 0
		elif index >= len(STEP_TABLE):
			index = len(STEP_TABLE) - 1
		self.index = index

		if isNeg:
			encoded |= 0x8
			predicted -= predicted_delta
		else:
			predicted += predicted_delta

		if predicted > 2**resolution:
			predicted = 2**resolution
		elif predicted < 0:
			predicted = 0
		self.predicted = predicted

		return encoded

class ByteAdpcmDecoder:
	def __init__(self, start_value, index):
		self.predicted = start_value
		self.index = index
		if index >= len(STEP_TABLE):
			raise ValueError('Invalid index')

	def decode(self, nibble):
		index = self.index
		step = STEP_TABLE[index]
		predicted = self.predicted

		predicted_delta = 0
		if nibble & 4:
			predicted_delta = step

		step >>= 1
		if nibble & 2:
			predicted_delta += step

		step >>= 1
		if nibble & 1:
			predicted_delta += step

		step >>= 1
		predicted_delta += step

		if nibble & 8:
			predicted -= predicted_delta
		else:
			predicted += predicted_delta

		if predicted > 2**resolution:
			predicted = 2**resolution
		elif predicted < 0:
			predicted = 0

		index += INDEX_TABLE[nibble & 0x7]
		if index < 0:
			index = 0
		elif index >= len(STEP_TABLE):
			index = len(STEP_TABLE) - 1

		self.index = index
		self.predicted = predicted
		return predicted



class ADPCM:
	def __init__(self, live_play=True, output_filename=None):
		self.output_filename = output_filename
		self.output_stream = None
		self.output_file = None
		self.live_play = live_play
		self.decoder = ByteAdpcmDecoder(0, 0)
		self.encoder = None

	def _open_stream(self, channels=1, rate=16000, sample_size=2, unsigned_sample_size=False):
		try:
			import pyaudio

			p = pyaudio.PyAudio()
			stream = p.open(
								format=pyaudio.get_format_from_width(
									sample_size,
									unsigned=unsigned_sample_size
								),
			                    channels=channels,
			                    rate=rate,
			                    output=True
			)
			return stream

		except ImportError:
			return None

	def _open_file(self, channels=1, rate=16000, sample_size=2, unsigned_sample_size=False):
		stream = wave.open(self.output_filename, 'wb')
		stream.setnchannels(channels)
		stream.setsampwidth(sample_size)
		stream.setframerate(rate)

		return stream

	def decode(self, samples):
		decoded_samples = b""
		for frame in samples:
			low = self.decoder.decode(frame >> 4)
			high = self.decoder.decode(frame & 0xF)
			try:
				decoded_samples += pack('H', low) + pack('H', high)
			except:
				pass
		return decoded_samples

	def convert_input_file(self, filename="/tmp/trololo.wav"):
		# buggy
		stream = wave.open(filename, "rb")
		nchannels = stream.getnchannels()
		sampwidth = stream.getsampwidth()
		rate = stream.getframerate()
		frames = stream.readframes(stream.getnframes())
		out = b""
		import audioop
		s = None
		(frag, ns) = audioop.lin2adpcm(frames,2,s)
		out += frag

		return ([
		RF4CE_Vendor_MSO_Audio_Start_Request(
			sample_rate = rate,
			#sample_rate=16000,
			resolution_bits=16,
			mic_channel_number=1,
			packet_size=84,
			interval=10,
			channel_number=3,
			duration=10
			)]
			+
			[
				RF4CE_Vendor_MSO_Audio_Data_Notify(
				samples=out[s:s+80]
				)
				for s in range(0, len(out), 80)
			]
		)

	def process_packet(self, packet):
		if RF4CE_Vendor_MSO_Audio_Start_Request in packet:
			if self.live_play:
				self.output_stream = self._open_stream()
			if self.output_filename:
				self.output_file = self._open_file()

		elif RF4CE_Vendor_MSO_Audio_Data_Notify in packet:
			if self.output_stream is not None or self.output_file is not None:
				decoded_samples = self.decode(packet.samples)
			if self.output_stream is not None:
				if self.live_play:
					self.output_stream.write(decoded_samples)
			if self.output_file is not None:
				self.output_file.writeframes(decoded_samples)

		elif RF4CE_Vendor_MSO_Audio_Stop_Request in packet or (RF4CE_Vendor_MSO_Audio in packet and packet.audio_cmd_id == 2):
			if self.output_stream is not None:
				if self.live_play:
					self.output_stream.close()
					self.output_stream = None
				if self.output_file is not None:
					self.output_file.close()
