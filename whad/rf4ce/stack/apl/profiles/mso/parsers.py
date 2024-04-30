from struct import pack, unpack

class InformationAttributeValue:
    @classmethod
    def pack(cls, value):
        return value

    @classmethod
    def unpack(cls, value):
        return value

class PeripheralIDsValue(InformationAttributeValue):
    @classmethod
    def pack(cls, value):
        if not isinstance(value, list):
            raise ValueError("pack")

        packed = b""
        for id in value:
            if not isinstance(id, int):
                raise ValueError("pack")
            packed += pack("I", id)
        return packed

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        nb_elements = len(value) // 4
        return list(unpack(nb_elements * "I", value))

class SoftwareVersioningValue(InformationAttributeValue):
    @classmethod
    def pack(cls, major, minor, revision, patch):
        if (
            not isinstance(major, int) or major > 255 or major < 0 or
            not isinstance(minor, int) or minor > 255 or minor < 0 or
            not isinstance(revision, int) or revision > 255 or revision < 0 or
            not isinstance(patch, int) or patch > 255 or patch < 0
        ):
            raise ValueError("pack")

        return bytes([major, minor, revision, patch])

    @classmethod
    def unpack(cls, value):
        return unpack("BBBB", value)

class IRDBVersioningValue(SoftwareVersioningValue):
    pass

class HardwareVersioningValue(InformationAttributeValue):
    @classmethod
    def pack(cls, manufacturer, model, revision, lot_code):
        if (
            not isinstance(manufacturer, int) or manufacturer > 15 or manufacturer < 0 or
            not isinstance(model, int) or model > 15 or model < 0 or
            not isinstance(revision, int) or revision > 255 or revision < 0 or
            not isinstance(lot_code, int) or lot_code > 4095 or lot_code < 0
        ):
            raise ValueError("pack")

        return bytes(
            [
                ((manufacturer & 0xF) << 4) | (model & 0xF),
                revision,
                (lot_code >> 8),
                (lot_code & 0xFF)
            ]
        )

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")
        manufacturer, model = value[0] >> 4, value[0] & 0x0F
        revision = value[1]
        lot_value = unpack(">H", value[2:])[0]
        return manufacturer, model, revision, lot_value

class VersioningValue(InformationAttributeValue):
    @classmethod
    def pack(cls, software, hardware, irdb):
        return (
            SoftwareVersioningValue.pack(*software) +
            HardwareVersioningValue.pack(*hardware) +
            IRDBVersioningValue.pack(*irdb)
        )

    @classmethod
    def unpack(cls,value):
        return (
            SoftwareVersioningValue.unpack(value[:4]),
            HardwareVersioningValue.unpack(value[4:8]),
            IRDBVersioningValue.unpack(value[8:]),
        )

class FlagsBatteryValue(InformationAttributeValue):
    @classmethod
    def pack(cls, battery_replacement, battery_charging, impending_doom):
        if (
            not isinstance(battery_replacement, bool) or
            not isinstance(battery_charging, bool) or
            not isinstance(impending_doom, bool)
        ):
            raise ValueError("pack")
        return bytes(
            [
                (int(battery_replacement) & 1) |
                ((int(battery_charging) & 1) >> 1) |
                ((int(impending_doom) & 1) >> 2)
            ]
        )

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        battery_replacement = bool(value[0] & 0x1)
        battery_charging = bool((value[0] & 0x2) >> 1)
        impending_doom = bool((value[0] & 0x4) >> 2)
        return (battery_replacement, battery_charging, impending_doom)


class VoltageLevelValue(InformationAttributeValue):
    @classmethod
    def pack(cls, level):
        # linear interpolation between 0V & 4V

        if level < 0 or level > 4:
            raise ValueError("pack")

        return bytes([int((level / 4) * 255)])

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (value[0] / 255) * 4

class BatteryStatusValue(InformationAttributeValue):
    @classmethod
    def pack(cls, flags, loaded_voltage_level, number_of_rf_codes_transmitted, number_of_ir_codes_transmitted, unloaded_voltage_level):
        return (
            FlagsBatteryValue.pack(*flags) +
            VoltageLevelValue.pack(loaded_voltage_level) +
            pack("I", number_of_rf_codes_transmitted) +
            pack("I", number_of_ir_codes_transmitted) +
            VoltageLevelValue.pack(unloaded_voltage_level)
        )

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            FlagsBatteryValue.unpack(value[0]) ,
            VoltageLevelValue.unpack(value[1]),
            unpack("I", value[2:6]),
            VoltageLevelValue.unpack(value[11])
        )

class ValidationConfigurationValue(InformationAttributeValue):
    @classmethod
    def pack(cls, auto_check_validation_period, link_lost_wait_time):
        if not isinstance(auto_check_validation_period, int) or not isinstance(link_lost_wait_time, int):
            raise ValueError("pack")
        return pack("H", auto_check_validation_period) + pack("H", link_lost_wait_time)

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            unpack("H", value[:2])[0],
            unpack("H", value[2:])[0]
        )

class IRRFFlagsValue(InformationAttributeValue):
    @classmethod
    def pack(cls, rf_pressed_specified, rf_repeated_specified, rf_released_specified, ir_specified, use_default, permanent):
        if (
            not isinstance(rf_pressed_specified, bool) or
            not isinstance(rf_repeated_specified, bool) or
            not isinstance(rf_released_specified, bool) or
            not isinstance(ir_specified, bool) or
            not isinstance(permanent, bool) or
            not isinstance(use_default, bool)
        ):
            raise ValueError("pack")

        return bytes(
            [
                (int(rf_pressed_specified) & 0x1) |
                ((int(rf_repeated_specified) & 0x1) >> 1) |
                ((int(rf_released_specified) & 0x1) >> 2) |
                ((int(ir_specified) & 0x1) >> 3) |
                ((int(use_default) & 0x1) >> 6) |
                ((int(permanent) & 0x1) >> 7)
            ]
        )

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            value[0] & 0b00000001,
            (value[0] & 0b00000010) >> 1,
            (value[0] & 0b00000100) >> 2,
            (value[0] & 0b00001000) >> 3,
            (value[0] & 0b01000000) >> 6,
            (value[0] & 0b10000000) >> 7
        )

class RFConfigValue(InformationAttributeValue):
    @classmethod
    def pack(cls, minimum_number_of_transmissions, keep_transmitting_until_key_release, short_retry):
        if (
            not isinstance(minimum_number_of_transmissions, int) or
            not isinstance(keep_transmitting_until_key_release, bool) or
            not isinstance(short_retry, bool)
        ):
            raise ValueError("pack")

        return bytes([
            (minimum_number_of_transmissions & 0x0F) |
            ((int(keep_transmitting_until_key_release)  & 1) << 4) |
            ((int(short_retry)  & 1) << 5)
        ])

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            (minimum_number_of_transmissions & 0x0F),
            (keep_transmitting_until_key_release & 0x10) >> 4,
            (short_retry & 0x20) >> 5
        )

class IRConfigValue(InformationAttributeValue):
    @classmethod
    def pack(cls, minimum_number_of_transmissions, keep_transmitting_until_key_release, tweak_database):
        if (
            not isinstance(minimum_number_of_transmissions, int) or
            not isinstance(keep_transmitting_until_key_release, bool) or
            not isinstance(tweak_database, bool)
        ):
            raise ValueError("pack")

        return bytes([
            (minimum_number_of_transmissions & 0x0F) |
            ((int(keep_transmitting_until_key_release)  & 1) << 4) |
            ((int(tweak_database)  & 1) << 6)
        ])

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            (minimum_number_of_transmissions & 0x0F),
            (keep_transmitting_until_key_release & 0x10) >> 4,
            (tweak_database & 0x40) >> 6
        )

class TXOptionsValue(InformationAttributeValue):
    @classmethod
    def pack(cls, broadcast_transmission, extended_address_mode, acknowledgement_mode, security_enabled, channel_agility_mode, channel_normalization_mode, vendor_specific):
        if (
            not isinstance(broadcast_transmission, bool) or
            not isinstance(extended_address_mode, bool) or
            not isinstance(acknowledgement_mode, bool) or
            not isinstance(security_enabled, bool) or
            not isinstance(channel_agility_mode, bool) or
            not isinstance(channel_normalization_mode, bool) or
            not isinstance(vendor_specific, bool)
        ):
            raise ValueError("pack")

        return bytes(
            [
                (int(broadcast_transmission) & 0x1) |
                ((int(extended_address_mode) & 0x1) << 1) |
                ((int(acknowledgement_mode) & 0x1) << 2) |
                ((int(security_enabled) & 0x1) << 3) |
                ((int(channel_agility_mode) & 0x1) << 4) |
                ((int(channel_normalization_mode) & 0x1) << 5) |
                ((int(vendor_specific) & 0x1) << 6)
            ]
        )

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            (value[0] & 0b00000001),
            (value[0] & 0b00000010) >> 1,
            (value[0] & 0b00000100) >> 2,
            (value[0] & 0b00001000) >> 3,
            (value[0] & 0b00010000) >> 4,
            (value[0] & 0b00100000) >> 5,
            (value[0] & 0b01000000) >> 6
        )

class RFDescriptorValue(InformationAttributeValue):
    @classmethod
    def pack(cls, rf_config, tx_options, payload):
        if not isinstance(payload, bytes):
            raise ValueError("pack")

        return RFConfigValue.pack(*rf_config) + TXOptionsValue.pack(*tx_options) + bytes([len(payload)]) + payload

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            RFConfigValue.unpack(value[0]),
            TXOptionsValue.unpack(value[1]),
            value[2],
            value[3:]
        )


class IRDescriptorValue(InformationAttributeValue):
    @classmethod
    def pack(cls, ir_config, ir_code):
        if not isinstance(ir_code, bytes):
            raise ValueError("pack")

        return IRConfigValue.pack(*ir_config) + bytes([len(ir_code)]) + ir_code

    @classmethod
    def unpack(cls, value):
        if not isinstance(value, bytes):
            raise ValueError("unpack")

        return (
            IRConfigValue.unpack(value[0]),
            value[1],
            value[2:]
        )


class IRRFElementValue(InformationAttributeValue):
    @classmethod
    def pack(cls, flags, rf_pressed_descriptor, rf_repeated_descriptor, rf_released_descriptor, ir_descriptor):
        rf_pressed_specified = flags[0]
        rf_repeated_specified = flags[1]
        rf_released_specified = flags[2]
        ir_specified = flags[3]

        return (
            IRRFFlagsValue.pack(*flags) +
            (RFDescriptorValue.pack(*rf_pressed_descriptor) if rf_pressed_specified else b"") +
            (RFDescriptorValue.pack(*rf_repeated_descriptor) if rf_repeated_specified else b"") +
            (RFDescriptorValue.pack(*rf_released_descriptor) if rf_released_specified else b"") +
            (IRDescriptorValue.pack(*ir_descriptor) if ir_specified else b"")
        )

    @classmethod
    def unpack(cls, value):
        flags = IRRFFlagsValue.unpack(value[0])
        (
            rf_pressed_specified,
            rf_repeated_specified,
            rf_released_specified,
            ir_specified,
            use_default,
            permanent
        ) = flags

        value = value[1:]

        descriptors = []
        for i in (rf_pressed_specified, rf_repeated_specified, rf_released_descriptor):
             descriptor, value = RFDescriptorValue.unpack(value[:3 + value[2]]), value[3 + value[2]:]
             descriptors.append(descriptor)

        descriptors.append(IRDescriptorValue(value))
        return (flags, *descriptors)
