
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

		if predicted > 255:
			predicted = 255
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
		print(self.predicted)
		return predicted
