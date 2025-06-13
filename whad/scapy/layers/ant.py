from scapy.packet import Packet, bind_layers
from scapy.fields import StrFixedLenField, ByteField, ByteEnumField, \
 	BitField, BitEnumField,LEX3BytesField, LEShortField, LEIntField, \
	SignedByteField, ShortField, LEShortEnumField

ANT_MANUFACTURERS_ID = {
	"Garmin": 1,
	"GarminFr405Antfs": 2,
	"Zephyr": 3,
	"Dayton": 4,
	"Idt": 5,
	"Srm": 6,
	"Quarq": 7,
	"Ibike": 8,
	"Saris": 9,
	"SparkHk": 10,
	"Tanita": 11,
	"Echowell": 12,
	"DynastreamOem": 13,
	"Nautilus": 14,
	"Dynastream": 15,
	"Timex": 16,
	"Metrigear": 17,
	"Xelic": 18,
	"Beurer": 19,
	"Cardiosport": 20,
	"AAndD": 21,
	"Hmm": 22,
	"Suunto": 23,
	"ThitaElektronik": 24,
	"Gpulse": 25,
	"CleanMobile": 26,
	"PedalBrain": 27,
	"Peaksware": 28,
	"Saxonar": 29,
	"LemondFitness": 30,
	"Dexcom": 31,
	"WahooFitness": 32,
	"OctaneFitness": 33,
	"Archinoetics": 34,
	"TheHurtBox": 35,
	"CitizenSystems": 36,
	"Magellan": 37,
	"Osynce": 38,
	"Holux": 39,
	"Concept2": 40,
	"Shimano": 41,
	"OneGiantLeap": 42,
	"AceSensor": 43,
	"BrimBrothers": 44,
	"Xplova": 45,
	"PerceptionDigital": 46,
	"Bf1systems": 47,
	"Pioneer": 48,
	"Spantec": 49,
	"Metalogics": 50,
	"_4iiiis": 51,
	"SeikoEpson": 52,
	"SeikoEpsonOem": 53,
	"IforPowell": 54,
	"MaxwellGuider": 55,
	"StarTrac": 56,
	"Breakaway": 57,
	"AlatechTechnologyLtd": 58,
	"MioTechnologyEurope": 59,
	"Rotor": 60,
	"Geonaute": 61,
	"IdBike": 62,
	"Specialized": 63,
	"Wtek": 64,
	"PhysicalEnterprises": 65,
	"NorthPoleEngineering": 66,
	"Bkool": 67,
	"Cateye": 68,
	"StagesCycling": 69,
	"Sigmasport": 70,
	"Tomtom": 71,
	"Peripedal": 72,
	"Wattbike": 73,
	"Moxy": 76,
	"Ciclosport": 77,
	"Powerbahn": 78,
	"AcornProjectsAps": 79,
	"Lifebeam": 80,
	"Bontrager": 81,
	"Wellgo": 82,
	"Scosche": 83,
	"Magura": 84,
	"Woodway": 85,
	"Elite": 86,
	"NielsenKellerman": 87,
	"DkCity": 88,
	"Tacx": 89,
	"DirectionTechnology": 90,
	"Magtonic": 91,
	"_1partcarbon": 92,
	"InsideRideTechnologies": 93,
	"SoundOfMotion": 94,
	"Stryd": 95,
	"Icg": 96,
	"MiPulse": 97,
	"BsxAthletics": 98,
	"Look": 99,
	"CampagnoloSrl": 100,
	"BodyBikeSmart": 101,
	"Praxisworks": 102,
	"LimitsTechnology": 103,
	"TopactionTechnology": 104,
	"Cosinuss": 105,
	"Fitcare": 106,
	"Magene": 107,
	"GiantManufacturingCo": 108,
	"Tigrasport": 109,
	"Salutron": 110,
	"Technogym": 111,
	"BrytonSensors": 112,
	"LatitudeLimited": 113,
	"SoaringTechnology": 114,
	"Igpsport": 115,
	"Thinkrider": 116,
	"GopherSport": 117,
	"Waterrower": 118,
	"Orangetheory": 119,
	"Inpeak": 120,
	"Kinetic": 121,
	"JohnsonHealthTech": 122,
	"PolarElectro": 123,
	"Seesense": 124,
	"NciTechnology": 125,
	"Iqsquare": 126,
	"Leomo": 127,
	"IfitCom": 128,
	"CorosByte": 129,
	"VersaDesign": 130,
	"Chileaf": 131,
	"Cycplus": 132,
	"GravaaByte": 133,
	"Sigeyi": 134,
	"Coospo": 135,
	"Geoid": 136,
	"Bosch": 137,
	"Kyto": 138,
	"KineticSports": 139,
	"DecathlonByte": 140,
	"TqSystems": 141,
	"Development": 255,
	"Healthandlife": 257,
	"Lezyne": 258,
	"ScribeLabs": 259,
	"Zwift": 260,
	"Watteam": 261,
	"Recon": 262,
	"FaveroElectronics": 263,
	"Dynovelo": 264,
	"Strava": 265,
	"Precor": 266,
	"Bryton": 267,
	"Sram": 268,
	"Navman": 269,
	"Cobi": 270,
	"Spivi": 271,
	"MioMagellan": 272,
	"Evesports": 273,
	"SensitivusGauge": 274,
	"Podoon": 275,
	"LifeTimeFitness": 276,
	"FalcoEMotors": 277,
	"Minoura": 278,
	"Cycliq": 279,
	"Luxottica": 280,
	"TrainerRoad": 281,
	"TheSufferfest": 282,
	"Fullspeedahead": 283,
	"Virtualtraining": 284,
	"Feedbacksports": 285,
	"Omata": 286,
	"Vdo": 287,
	"Magneticdays": 288,
	"Hammerhead": 289,
	"KineticByKurt": 290,
	"Shapelog": 291,
	"Dabuziduo": 292,
	"Jetblack": 293,
	"Coros": 294,
	"Virtugo": 295,
	"Velosense": 296,
	"Cycligentinc": 297,
	"Trailforks": 298,
	"MahleEbikemotion": 299,
	"Nurvv": 300,
	"Microprogram": 301,
	"Zone5cloud": 302,
	"Greenteg": 303,
	"YamahaMotors": 304,
	"Whoop": 305,
	"Gravaa": 306,
	"Onelap": 307,
	"MonarkExercise": 308,
	"Form": 309,
	"Decathlon": 310,
	"Syncros": 311,
	"Heatup": 312,
	"Cannondale": 313,
	"TrueFitness": 314,
	"RGTCycling": 315,
	"Vasa": 316,
	"RaceRepublic": 317,
	"Actigraphcorp": 5759,
	"Invalid": 0xFFFF,
}

# address[0:2] seems static: 0x3ba3
# device ID : address[2]
# address [3:5] seems static: 0x0001
 

class AntAddressField(StrFixedLenField):
	def __init__(self, name, default):
		StrFixedLenField.__init__(self, name, default,length=5)

	def i2h(self,pkt,x):
		return ":".join(["{:02x}".format(i) for i in x])

	def i2repr(self,pkt,x):
		return ":".join(["{:02x}".format(i) for i in x])
		
	def any2i(self,pkt,x):
		if isinstance(x,str):
			x = bytes.fromhex(x.replace(":",""))
		return x

class ANT_Hdr(Packet):
	name = "ANT packet"
	fields_desc = [
		LEShortField("preamble", None),
		LEShortField("device_number", None),
		ByteField("device_type", None),
		ByteField("transmission_type",None),
		BitEnumField("broadcast",None,1, {0:"broadcast", 1:"ack/burst"}),
		BitEnumField("ack", None, 1, {0:False, 1: True}),
		BitEnumField("end",None, 1, {0:False, 1:True}),
		BitField("count",None, 1),
		BitEnumField("slot", None, 1, {0:False, 1:True}),
		BitField("unknown", None, 3),
	]

class  ANT_Plus_Header_Hdr(Packet):
	name = "ANT+ Header"
	fields_desc = [
	]


	def guess_payload_class(self, payload):
		"""Guess payload content based on payload size and content.
		"""
		if self.underlayer is not None and len(payload) > 0 and self.underlayer.device_type in ANT_PLUS_PROFILES.keys():
			return ANT_PLUS_PROFILES[self.underlayer.device_type]
		else:
			return Packet.guess_payload_class(self, payload)

class ANT_Plus_HR_Header_Hdr(Packet):
	name = "ANT Heart Rate Header"
	fields_desc = [
		BitField("toggle_bit", None, 1),
		BitField("data_page_number", None, 7),
	]


class ANT_HR_Default_Data_Page(Packet):
	name = "ANT Heart Rate Default Data Page"
	fields_desc = [
		LEX3BytesField("reserved",0xFFFFFF)
	]

class ANT_HR_Cumulative_Operating_Time_Data_Page(Packet):
	name = "ANT Heart Rate Cumulative Operating Time Data Page"
	fields_desc = [
		LEX3BytesField("cumulative_operating_time",None)
	]

class ANT_HR_Manufacturer_Information_Data_Page(Packet):
	name = "ANT Heart Rate Manufacturer Information Data Page"
	fields_desc = [
		ByteEnumField("manufacturer_id",None,ANT_MANUFACTURERS_ID),
		LEShortField("serial_number", None)
	]

class ANT_HR_Product_Information_Data_Page(Packet):
	name = "ANT Heart Rate Product Information Data Page"
	fields_desc = [
		ByteField("hardware_version",None),
		ByteField("software_version",None),
		ByteField("model_number", None)
	]


class ANT_HR_Previous_Heart_Beat_Data_Page(Packet):
	name = "ANT Heart Rate Previous Heart Beat Data Page"
	fields_desc = [
		ByteField("manufacturer", None),
		LEShortField("previous_heart_beat",None)
	]

class ANT_HR_Swim_Interval_Summary_Data_Page(Packet):
	name = "ANT Heart Rate Swim Interval Summary Data Page"
	fields_desc = [
		ByteField("interval_average_heart_rate",None),
		ByteField("interval_maximum_heart_rate",None),
		ByteField("session_average_heart_rate", None)
	]


class ANT_HR_Capabilities_Data_Page(Packet):
	name = "ANT Heart Rate Capabilities Data Page"
	fields_desc = [
		ByteField("reserved_2",None),
		BitEnumField("manufacturer_specific_features_supported",None, 2, {1:"supported", 0:"non supported"}),
		BitField("reserved_3",0, 3),
		BitEnumField("extended_swimming_features_supported",0, 1, {1:"supported", 0:"non supported"}),
		BitEnumField("extended_cycling_features_supported",0, 1, {1:"supported", 0:"non supported"}),
		BitEnumField("extended_running_features_supported",0, 1, {1:"supported", 0:"non supported"}),

		BitEnumField("manufacturer_specific_features_enabled",None, 2, {1:"enabled", 0:"disabled"}),
		BitField("reserved_4",0, 3),
		BitEnumField("extended_swimming_features_enabled",0, 1, {1:"enabled", 0:"disabled"}),
		BitEnumField("extended_cycling_features_enabled",0, 1, {1:"enabled", 0:"disabled"}),
		BitEnumField("extended_running_features_enabled",0, 1, {1:"enabled", 0:"disabled"}),
	]


class ANT_HR_Battery_Status_Data_Page(Packet):
	name = "ANT Heart Rate Battery Status Data Page"
	fields_desc = [
		ByteField("battery_level",None),
		ByteField("fractional_battery_voltage",None),
		ByteField("coarse_battery_voltage",None),

	]

class ANT_Request_Data_Page(Packet):
	name = "ANT Request Data Page"
	fields_desc = [
		LEIntField("reserved", 0xFFFFFFFF),
		BitField("requested_transmission_response_using_ack", None, 1),
		BitField("requested_transmission_response_count", None, 7),
		ByteField("requested_page_number", None),
		ByteEnumField("command_type",0x01,  {0x01 : "request_data_page"})
	]


class ANT_Mode_Setting_Page(Packet):
	name = "ANT Mode Setting Page"
	fields_desc = [
		LEIntField("reserved", 0xFFFFFFFF),
		LEShortField("reserved2", 0xFFFF),
		ByteEnumField("sport_mode",None,  {0x01 : "running", 0x02 : "cycling", 0x03 : "swimming"})
	]

class ANT_HR_Common_Payload(Packet):
	name = "ANT Heart Rate Common Payload"
	fields_desc = [
		LEShortField("heart_beat_event_time", None),
		ByteField("heart_beat_count", None),
		ByteField("computed_heart_rate", None)
	]



class ANT_Plus_Ranging_Header_Hdr(Packet):
	name = "ANT Ranging Header"
	fields_desc = [
		ByteField("data_page_number", None)
	]

class ANT_Ranging_Measurement_Data_Page(Packet):
	name = "ANT Ranging Measurement Data Data Page"
	fields_desc = [
		LEShortField("reserved", 0x0000),
		SignedByteField("board_temperature", None),
		ByteField("reserved_2", 0xFF),
		ByteField("event_count", None),
		ShortField("distance", None)
	]


class ANT_Ranging_Set_Measurement_Mode_Data_Page(Packet):
	name = "ANT Ranging Set Measurement Mode Data Page"
	fields_desc = [
		ByteField("sequence_number", None),
		LEShortField("reserved", 0xFFFF),
		ByteEnumField("measurement_mode", None, {0x00:"asynchronous_mode", 0x01 : "synchronous_mode", 0xFF: "always_on"}),
		LEShortField("reserved_2", 0xFFFF),
		ByteField("measurement_interval_delay", None),
	]

class ANT_Ranging_Trigger_Distance_Measurement(Packet):
	name = "ANT Ranging Trigger Distance Measurement Data Page"
	fields_desc = [
		ByteField("sequence_number", None),
		LEIntField("reserved", 0xFFFFFFFF),
		LEShortField("reserved_2", 0xFFFF),
	]


class ANT_Plus_Bicycle_Speed_And_Cadence(Packet):
	name = "ANT Bicycle Speed and Cadence"
	fields_desc = [
		LEShortField("bike_cadence_event_time", None),
		LEShortField("cumulative_cadence_revolution_count", None),
		LEShortField("bike_speed_event_time", None),
		LEShortField("cumulative_speed_revolution_count", None),
	]

class ANT_Plus_Bicycle_Speed_Header_Hdr(Packet):
	name = "ANT Bicycle Speed Header"
	fields_desc = [
	BitField("toggle_bit", None, 1),
	BitField("data_page_number", None, 7),
	]


class ANT_Bicycle_Speed_Default_Data_Page(Packet):
	name = "ANT Bicycle Speed Default Data Page"
	fields_desc = [
		LEX3BytesField("reserved",0xFFFFFF),
		LEShortField("bike_speed_event_time", None),
		LEShortField("cumulative_speed_revolution_count", None),
	]


class ANT_Bicycle_Speed_Cumulative_Operating_Time_Data_Page(Packet):
	name = "ANT Bicycle Speed Cumulative Operating Time Data Page"
	fields_desc = [
		LEX3BytesField("cumulative_operating_time",None),
		LEShortField("bike_speed_event_time", None),
		LEShortField("cumulative_speed_revolution_count", None),
	]


class ANT_Bicycle_Speed_Manufacturer_Information_Data_Page(Packet):
	name = "ANT Bicycle Speed Manufacturer Information Data Page"
	fields_desc = [
		ByteEnumField("manufacturer_id",None,ANT_MANUFACTURERS_ID),
		LEShortField("serial_number", None),
		LEShortField("bike_speed_event_time", None),
		LEShortField("cumulative_speed_revolution_count", None),
	]

class ANT_Bicycle_Speed_Product_Information_Data_Page(Packet):
	name = "ANT Bicycle Speed Product Information Data Page"
	fields_desc = [
		ByteField("hardware_version",None),
		ByteField("software_version",None),
		ByteField("model_number",None),
		LEShortField("bike_speed_event_time", None),
		LEShortField("cumulative_speed_revolution_count", None),
	]

class ANT_Bicycle_Speed_Battery_Status_Data_Page(Packet):
	name = "ANT Bicycle Speed Battery Status Data Page"
	fields_desc = [
		ByteField("reserved",0xFF),
		ByteField("fractional_battery_voltage",None),
		BitField("reserved_2", None, 1),
		BitEnumField("battery_status", None, 3,  {0x00 : "reserved", 0x01 : "new", 0x02: "good", 0x03 : "ok", 0x04: "low", 0x05 : "critical", 0x06 : "reserved", 0x07: "invalid"}),
		BitField("coarse_battery_voltage", None, 4),
		LEShortField("bike_speed_event_time", None),
		LEShortField("cumulative_speed_revolution_count", None),

	]


class ANT_Bicycle_Speed_Motion_And_Cadence_Data_Page(Packet):
	name = "ANT Bicycle Speed Motion and Cadence Data Page"
	fields_desc = [
		ByteField("flags",None),
		LEShortField("reserved", 0xFFFF),
		LEShortField("bike_speed_event_time", None),
		LEShortField("cumulative_speed_revolution_count", None),
	]

class ANT_Plus_Bicycle_Cadence_Header_Hdr(Packet):
	name = "ANT Bicycle Cadence Header"
	fields_desc = [
	BitField("toggle_bit", None, 1),
	BitField("data_page_number", None, 7),
	]

class ANT_Bicycle_Cadence_Default_Data_Page(Packet):
	name = "ANT Bicycle Cadence Default Data Page"
	fields_desc = [
		LEX3BytesField("reserved",0xFFFFFF),
		LEShortField("bike_cadence_event_time", None),
		LEShortField("cumulative_cadence_revolution_count", None),

	]

class ANT_Bicycle_Cadence_Cumulative_Operating_Time_Data_Page(Packet):
	name = "ANT Bicycle Cadence Cumulative Operating Time Data Page"
	fields_desc = [
		LEX3BytesField("cumulative_operating_time",None),
		LEShortField("bike_cadence_event_time", None),
		LEShortField("cumulative_cadence_revolution_count", None),
	]

class ANT_Bicycle_Cadence_Manufacturer_Information_Data_Page(Packet):
	name = "ANT Bicycle Cadence Manufacturer Information Data Page"
	fields_desc = [
		ByteEnumField("manufacturer_id",None,ANT_MANUFACTURERS_ID),
		LEShortField("serial_number", None),
		LEShortField("bike_cadence_event_time", None),
		LEShortField("cumulative_cadence_revolution_count", None),

	]

class ANT_Bicycle_Cadence_Product_Information_Data_Page(Packet):
	name = "ANT Bicycle Cadence Product Information Data Page"
	fields_desc = [
		ByteField("hardware_version",None),
		ByteField("software_version",None),
		ByteField("model_number",None),
		LEShortField("bike_cadence_event_time", None),
		LEShortField("cumulative_cadence_revolution_count", None),

	]

class ANT_Bicycle_Cadence_Battery_Status_Data_Page(Packet):
	name = "ANT Bicycle Cadence Battery Status Data Page"
	fields_desc = [
		ByteField("reserved",0xFF),
		ByteField("fractional_battery_voltage",None),
		BitField("reserved_2", None, 1),
		BitEnumField("battery_status", None, 3,  {0x00 : "reserved", 0x01 : "new", 0x02: "good", 0x03 : "ok", 0x04: "low", 0x05 : "critical", 0x06 : "reserved", 0x07: "invalid"}),
		BitField("coarse_battery_voltage", None, 4),
		LEShortField("bike_cadence_event_time", None),
		LEShortField("cumulative_cadence_revolution_count", None),

	]


class ANT_Bicycle_Cadence_Motion_And_Cadence_Data_Page(Packet):
	name = "ANT Bicycle Cadence Motion and Cadence Data Page"
	fields_desc = [
		ByteField("flags",None),
		LEShortField("reserved", 0xFFFF),
		LEShortField("bike_cadence_event_time", None),
		LEShortField("cumulative_cadence_revolution_count", None),

	]


class  ANT_FS_Header_Hdr(Packet):
	name = "ANT FS Header"
	fields_desc = [
	]

class ANT_FS_Type_Hdr(Packet):
	name = "ANT FS Type"
	fields_desc = [
		ByteEnumField("packet_type",None,{0x43:"Beacon", 0x44:"Command / Response"})
	]

class ANT_FS_Beacon_Packet(Packet):
	name = "ANT FS Beacon Packet"
	fields_desc = [
			BitField("reserved",None, 2),
			BitEnumField("data",None, 1, {0:False,1:True}),
			BitEnumField("upload",None, 1, {0:False,1:True}),
			BitEnumField("pairing",None, 1, {0:False,1:True}),
			BitEnumField("period",None, 3, {
											0: "0.5 Hz (65535)",
											1: "1 Hz (32768)",
											2: "2 Hz (16384)",
											3: "4 Hz (8192)",
											4: "8 Hz (4096)",
											7: "match established",
											}),
			ByteEnumField("state",None, {
											0: "link",
											1: "auth",
											2: "transport",
											3: "busy",
										}),
			ByteEnumField("auth_type",None, {
											0: "pass-through",
											1: "n/a",
											2: "pairing",
											3: "passkey & pairing",
										}),
	]


class ANT_FS_Beacon_Link_Packet(Packet):
	name = "ANT FS Beacon Link Packet"
	fields_desc = [
		LEShortField("dev_type",None),
		LEShortEnumField("manufacturer_id",None, ANT_MANUFACTURERS_ID)
	]


class ANT_FS_Beacon_Auth_Packet(Packet):
	name = "ANT FS Beacon Auth Packet"
	fields_desc = [
		LEIntField("host_serial",None)
	]


class ANT_FS_Beacon_Transport_Packet(Packet):
	name = "ANT FS Beacon Transport Packet"
	fields_desc = [
		LEIntField("host_serial",None)
	]

class ANT_FS_Command_Or_Response_Packet(Packet):
	name = "ANT FS Command or Response Packet"
	fields_desc = [
		ByteEnumField("cmd_or_resp_type", None, {
												# ANTFS Commands
												0x02: "link_cmd",
												0x03: "disconnect_cmd",
												0x04: "auth_cmd",
												0x05: "ping_cmd",
												0x09: "download_req_cmd",
												0x0a: "upload_req_cmd",
												0x0b: "erase_req_cmd",
												0x0c: "upload_data_cmd",
												# ANTFS Responses
												0x84: "auth_resp",
												0x89: "download_req_resp",
												0x8a: "upload_req_resp",
												0x8b: "erase_resp",
												0x8c: "upload_data_resp",
		})
	]


class ANT_FS_Link_Command_Packet(Packet):
	name = "ANT FS Link Command Packet"
	fields_desc = [
		ByteField("frequency", None),
		ByteEnumField("period", None, {
										0: "0.5 Hz (65535)",
										1: "1 Hz (32768)",
										2: "2 Hz (16384)",
										3: "4 Hz (8192)",
										4: "8 Hz (4096)",
										7: "match established",
		}),
		LEIntField("host_serial",None)
	]

class ANT_FS_Disconnect_Command_Packet(Packet):
	name = "ANT FS Disconnect Command Packet"
	fields_desc = [
		ByteEnumField("disconnect_type", None, {0 : "return to link", 1 : "return to broadcast"}),
		ByteField("time_duration", None),
		ByteField("application_duration", None)
	]


class ANT_FS_Auth_Command_Packet(Packet):
	name = "ANT FS Auth Command Packet"
	fields_desc = [
		ByteEnumField("auth_type", None, {
												0: "pass-through",
												1: "request serial",
												2: "request pairing",
												3: "request passkey",
		}),
		ByteField("auth_string_length", None),
		LEIntField("host_serial",None)
	]


class ANT_FS_Ping_Command_Packet(Packet):
	name = "ANT FS Ping Command Packet"
	fields_desc = []



class ANT_FS_Download_Request_Command_Packet(Packet):
	name = "ANT FS Download Request Command Packet"
	fields_desc = [
		LEShortField("index", None),
		LEIntField("offset", None)
	]


class ANT_FS_Upload_Request_Command_Packet(Packet):
	name = "ANT FS Upload Request Command Packet"
	fields_desc = [
		LEShortField("index", None),
		LEIntField("max_size", None)
	]


class ANT_FS_Upload_Data_Command_Packet(Packet):
	name = "ANT FS Upload Data Command Packet"
	fields_desc = [
		LEShortField("crc_seed", None),
		LEIntField("offset", None)
	]

class ANT_FS_Erase_Command_Packet(Packet):
	name = "ANT FS Erase Request Command Packet"
	fields_desc = [
		LEShortField("index", None)
	]


class ANT_FS_Auth_Response_Packet(Packet):
	name = "ANT FS Auth Response Packet"
	fields_desc = [
		ByteEnumField("response", None, {
											0: "response to serial req.",
											1: "accept",
											2: "reject",
		}),
		ByteField("auth_string_length", None),
		LEIntField("client_serial",None)
	]

class ANT_FS_Download_Request_Response_Packet(Packet):
	name = "ANT FS Download Request Response Packet"
	fields_desc = [
		ByteEnumField("response", None, {
											0: "ANTFS_OK",
											1: "ANTFS_ENOENT",
											2: "ANTFS_EACCESS",
											3: "ANTFS_ENOTREADY",
											4: "ANTFS_EINVAL",
											5: "ANTFS_ECRC",
		}),
		LEIntField("remaining", None)
	]

class ANT_FS_Upload_Request_Response_Packet(Packet):
	name = "ANT FS Upload Request Response Packet"
	fields_desc = [
		ByteEnumField("response", None, {
											0: "ANTFS_OK",
											1: "ANTFS_ENOENT",
											2: "ANTFS_EACCESS",
											3: "ANTFS_ENOSPC",
											4: "ANTFS_EINVAL",
											5: "ANTFS_ENOTREADY",
		}),
		LEIntField("last_offset", None)
	]


class ANT_FS_Upload_Data_Response_Packet(Packet):
	name = "ANT FS Upload Data Response Packet"
	fields_desc = [
		# ???
	]


class ANT_FS_Erase_Response_Packet(Packet):
	name = "ANT FS Erase Response Packet"
	fields_desc = [
		ByteEnumField("response", None, {
											0: "OK",
											1: "FAILED",
											2: "ENOTREADY",
		})
	]

ANT_PLUS_PROFILES = {
	120 : ANT_Plus_HR_Header_Hdr, 
	121 : ANT_Plus_Bicycle_Speed_And_Cadence, 
	122 : ANT_Plus_Bicycle_Cadence_Header_Hdr, 
	123 : ANT_Plus_Bicycle_Speed_Header_Hdr, 
	16  : ANT_Plus_Ranging_Header_Hdr 
}
bind_layers(ANT_Hdr, ANT_Plus_Header_Hdr, preamble=0xc5a6)
bind_layers(ANT_Hdr, ANT_FS_Header_Hdr, preamble=0xa33b)
bind_layers(ANT_FS_Header_Hdr, ANT_FS_Type_Hdr)

bind_layers(ANT_Plus_Header_Hdr,ANT_Plus_HR_Header_Hdr, device_type=120)
bind_layers(ANT_Plus_Header_Hdr,ANT_Plus_Bicycle_Speed_And_Cadence, device_type=121)
bind_layers(ANT_Plus_Header_Hdr,ANT_Plus_Bicycle_Cadence_Header_Hdr, device_type=122)
bind_layers(ANT_Plus_Header_Hdr,ANT_Plus_Bicycle_Speed_Header_Hdr, device_type=123)
bind_layers(ANT_Plus_Header_Hdr,ANT_Plus_Ranging_Header_Hdr, device_type=16)

bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Default_Data_Page,data_page_number=0)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Cumulative_Operating_Time_Data_Page,data_page_number=1)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Manufacturer_Information_Data_Page,data_page_number=2)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Product_Information_Data_Page,data_page_number=3)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Previous_Heart_Beat_Data_Page,data_page_number=4)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Swim_Interval_Summary_Data_Page, data_page_number=5)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Capabilities_Data_Page, data_page_number=6)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_HR_Battery_Status_Data_Page, data_page_number=7)

bind_layers(ANT_Plus_HR_Header_Hdr, ANT_Request_Data_Page, data_page_number=0x46)
bind_layers(ANT_Plus_HR_Header_Hdr, ANT_Mode_Setting_Page, data_page_number=0x4C)

bind_layers(ANT_HR_Default_Data_Page, ANT_HR_Common_Payload)
bind_layers(ANT_HR_Cumulative_Operating_Time_Data_Page, ANT_HR_Common_Payload)
bind_layers(ANT_HR_Previous_Heart_Beat_Data_Page, ANT_HR_Common_Payload)
bind_layers(ANT_HR_Manufacturer_Information_Data_Page, ANT_HR_Common_Payload)
bind_layers(ANT_HR_Product_Information_Data_Page, ANT_HR_Common_Payload)
bind_layers(ANT_HR_Capabilities_Data_Page, ANT_HR_Common_Payload)
bind_layers(ANT_HR_Battery_Status_Data_Page, ANT_HR_Common_Payload)


bind_layers(ANT_Plus_Ranging_Header_Hdr,ANT_Ranging_Measurement_Data_Page, data_page_number=0x10)
bind_layers(ANT_Plus_Ranging_Header_Hdr,ANT_Ranging_Set_Measurement_Mode_Data_Page, data_page_number=0x30)


bind_layers(ANT_Plus_Bicycle_Cadence_Header_Hdr,ANT_Bicycle_Cadence_Default_Data_Page,data_page_number=0)
bind_layers(ANT_Plus_Bicycle_Cadence_Header_Hdr,ANT_Bicycle_Cadence_Cumulative_Operating_Time_Data_Page,data_page_number=1)
bind_layers(ANT_Plus_Bicycle_Cadence_Header_Hdr,ANT_Bicycle_Cadence_Manufacturer_Information_Data_Page,data_page_number=2)
bind_layers(ANT_Plus_Bicycle_Cadence_Header_Hdr,ANT_Bicycle_Cadence_Product_Information_Data_Page,data_page_number=3)
bind_layers(ANT_Plus_Bicycle_Cadence_Header_Hdr,ANT_Bicycle_Cadence_Battery_Status_Data_Page, data_page_number=4)
bind_layers(ANT_Plus_Bicycle_Cadence_Header_Hdr,ANT_Bicycle_Cadence_Motion_And_Cadence_Data_Page,data_page_number=5)

bind_layers(ANT_Plus_Bicycle_Speed_Header_Hdr,ANT_Bicycle_Speed_Default_Data_Page,data_page_number=0)
bind_layers(ANT_Plus_Bicycle_Speed_Header_Hdr,ANT_Bicycle_Speed_Cumulative_Operating_Time_Data_Page,data_page_number=1)
bind_layers(ANT_Plus_Bicycle_Speed_Header_Hdr,ANT_Bicycle_Speed_Manufacturer_Information_Data_Page,data_page_number=2)
bind_layers(ANT_Plus_Bicycle_Speed_Header_Hdr,ANT_Bicycle_Speed_Product_Information_Data_Page,data_page_number=3)
bind_layers(ANT_Plus_Bicycle_Speed_Header_Hdr,ANT_Bicycle_Speed_Battery_Status_Data_Page, data_page_number=4)
bind_layers(ANT_Plus_Bicycle_Speed_Header_Hdr,ANT_Bicycle_Speed_Motion_And_Cadence_Data_Page,data_page_number=5)

bind_layers(ANT_FS_Type_Hdr,ANT_FS_Beacon_Packet, packet_type=0x43)
bind_layers(ANT_FS_Beacon_Packet,ANT_FS_Beacon_Link_Packet, state=0x00)
bind_layers(ANT_FS_Beacon_Packet,ANT_FS_Beacon_Auth_Packet, state=0x01)
bind_layers(ANT_FS_Beacon_Packet,ANT_FS_Beacon_Transport_Packet, state=0x02)

bind_layers(ANT_FS_Type_Hdr,ANT_FS_Command_Or_Response_Packet, packet_type=0x44)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Link_Command_Packet, cmd_or_resp_type=0x02)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Disconnect_Command_Packet, cmd_or_resp_type=0x03)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Auth_Command_Packet, cmd_or_resp_type=0x04)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Ping_Command_Packet, cmd_or_resp_type=0x05)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Download_Request_Command_Packet, cmd_or_resp_type=0x09)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Upload_Request_Command_Packet, cmd_or_resp_type=0x0a)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Erase_Command_Packet, cmd_or_resp_type=0x0b)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Upload_Data_Command_Packet, cmd_or_resp_type=0x0c)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Auth_Response_Packet, cmd_or_resp_type=0x84)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Download_Request_Response_Packet, cmd_or_resp_type=0x89)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Upload_Request_Response_Packet, cmd_or_resp_type=0x8a)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Erase_Response_Packet, cmd_or_resp_type=0x8b)
bind_layers(ANT_FS_Command_Or_Response_Packet,ANT_FS_Upload_Data_Response_Packet, cmd_or_resp_type=0x8c)