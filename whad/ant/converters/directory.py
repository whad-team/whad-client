"""This module provides the `Directory` class, representing an ANT-FS directory structure. 
It can be used to convert a directory object to its raw binary representation or convert 
the raw data to a Directory object.
"""
from enum import IntEnum
from whad.ant.exceptions import InvalidFileEntry, InvalidDirectory
from datetime import datetime
import time
from struct import pack, unpack

class TimeFormat(IntEnum):
    DATE_PARAMETER_THEN_LOCAL_TIME = 0
    LOCAL_TIME_ONLY = 1
    DATE_PARAMETER_ONLY = 2


class Permissions:
    def __init__(self, value = None, read=True, write=True, erase=True, archive=True, append=True, crypto=True):
        if value is not None:
            self.read =  (value & 0b10000000) > 0
            self.write = (value & 0b01000000) > 0
            self.erase = (value & 0b00100000) > 0
            self.archive = (value & 0b00010000) > 0
            self.append = (value & 0b00001000) > 0
            self.crypto = (value & 0b00000100) > 0
        else:
            self.read = read
            self.write = write
            self.erase = erase
            self.archive = archive
            self.append = append
            self.crypto = crypto


    @property
    def value(self):
        r = (1 if self.read else 0) << 7
        w = (1 if self.write else 0) << 6
        e =  (1 if self.erase else 0) << 5
        arch = (1 if self.archive else 0) << 4
        appe = (1 if self.append else 0) << 3
        c = (1 if self.crypto else 0) << 2

        return r | w | e | arch | appe | c

    
    def __repr__(self):
        permissions = []
        if self.read:
            permissions.append("Rd")
        if self.write:
            permissions.append("Wr")
        if self.erase:
            permissions.append("Er")
        if self.append:
            permissions.append("Ap")
        if self.archive:
            permissions.append("Ar")
        if self.crypto:
            permissions.append("Cr")
        return "Permissions(" + ", ".join(permissions)+ ")"

class FileEntry:

    @classmethod
    def parse(cls, values):
        entries = []
        while len(values) >= 16:
            entry_data = values[:16]
            values = values[16:]
            entries.append(FileEntry(value=entry_data))
        return entries

    def __init__(self, value=None, index=0, file_data_type=0, identifier=b"\x00\x00\x00", file_data_type_specific_flags=0, permissions=0, file_size = 0, date=None):
        if value is not None:
            if not isinstance(value, bytes) and len(value) != 16:
                raise InvalidFileEntry()

            self.index = unpack('H', value[:2])[0]
            self.file_data_type = value[2]
            self.identifier = value[3:6]
            self.file_data_type_specific_flags = value[6]
            self.permissions = Permissions(value=value[7])
            self.file_size = unpack('I', value[8:12])[0]
            self.date = unpack('I', value[12:16])[0]
        else:
            self.index = index
            self.file_data_type = file_data_type
            self.identifier = identifier
            self.file_data_type_specific_flags = file_data_type_specific_flags

            if isinstance(permissions, Permissions):
                self.permissions = permissions
            elif isinstance(permissions, int):
                self.permissions = Permissions(value=permissions)

            self.file_size = file_size
            if self.date is None:
                self.date =  int(time.time() - 631065600)
            else:
                self.date = self.date


    @property
    def value(self):
        value = b""
        value += pack('H', self.index)
        value += pack('B', self.file_data_type)
        value += self.identifier
        value += bytes([file_data_type_specific_flags])
        value += bytes([self.permissions.value])
        value += pack('I', self.file_size)
        value += pack('I', self.date)
        return value

    def __repr__(self):
        return "FileEntry - index = "  + str(self.index) + "| data type = " + str(self.file_data_type) + " | permissions = " + str(self.permissions) + " | date = " + datetime.utcfromtimestamp(self.date + 631065600).strftime('%Y-%m-%d %H:%M:%S') + " | size = " + str(self.file_size)

class Directory:
    def __init__(self, value=None, version=0, structure_length=16, time_format=TimeFormat.DATE_PARAMETER_THEN_LOCAL_TIME, current_system_time=None, last_modification_date=None, file_entries=[]):
        if value is not None:
            if not isinstance(value, bytes) and len(value) < 16:
                raise InvalidDirectory()

            self.version = ((value[0] & 0xF0) >> 4, value[0] & 0x0F)
            self.structure_length = value[1]
            self.time_format = TimeFormat.from_bytes(value[2:3]) 
            self.current_system_time = unpack('I', value[8:12])[0]
            self.last_modification_date = unpack('I', value[12:16])[0]
            self.file_entries = FileEntry.parse(value[16:])

        else:
            if (isinstance(version, tuple) or isinstance(version, list)) and len(version) == 2:
                self.version = (version[0], version[1])
            elif isinstance(version, int):
                self.version = ((version & 0xF0) >> 4, version & 0x0F)
            else:
                self.version = (0,0)

            self.structure_length = structure_length
            self.time_format = time_format

            if current_system_time is None:
                self.current_system_time = int(time.time() - 631065600)
            else:
                self.current_system_time = current_system_time
            
            if last_modification_date is None:
                self.last_modification_date = int(time.time() - 631065600)
            else:
                self.last_modification_date = last_modification_date


            if isinstance(file_entries, list):
                self.file_entries = file_entries
            elif isinstance(file_entries, bytes):
                self.file_entries = FileEntry.parse(file_entries)
            else:
                self.file_entries = []

    @property
    def value(self):
        value = (
            bytes([self.version[0] << 4 | self.version[1] & 0x0F, self.structure_length, time_format ]) +  
            pack('I', self.time_format) + pack('I', last_modification_date)
        )
        for entries in self.file_entries:
            value += entries.value
        return value

    def __repr__(self):
        return "Directory - version = " + str(self.version[0]) + "." + str(self.version[1]) + " | structure_length = " + str(self.structure_length) + " |  last_modification_date = " + datetime.utcfromtimestamp(self.last_modification_date + 631065600).strftime('%Y-%m-%d %H:%M:%S') + " - entries = \n\t" + "\n\t".join([str(entry) for entry in self.file_entries]) + "\n"