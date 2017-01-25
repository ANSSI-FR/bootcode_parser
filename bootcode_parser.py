#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from abc import ABCMeta, abstractmethod
import logging
import hashlib
import construct
import csv
import os
import capstone
import capstone.x86
import sys


BOOTRECORD_WHITELIST_PATH = os.path.join(os.path.dirname(__file__), 'data', 'bootrecord_whitelist.csv')


class BootRecord(object):
    __metaclass__ = ABCMeta

    def __init__(self, fileObject, size, offset=None, whitelist=()):
        """
            Default constructor which loads the raw data from a file.
            No sanity check is performed on the size or existence of the file.
        """
        # Common to MBR, VBR and IPL
        self._suspiciousBehaviour = []
        self._signature = []
        self._codeHash = None
        # MBR-specific
        self._partTable = []
        self._diskSignature = None
        # VBR-specific
        self._oemId = None

        self._whitelist = whitelist
        self._sample = fileObject.name
        self._offset = offset

        self._logger = logging.LoggerAdapter(logging.getLogger(__file__),
                                             {'objectid': self._sample, 'stage': self._type})

        self._raw = fileObject.read(size)
        self._parse()

    def __eq__(self, other):
        return self._raw == other.getRaw()

    def __ne__(self, other):
        return self._raw != other.getRaw()

    @abstractmethod
    def _parse(self):
        """
            Abstract private method called upon initialization to unpack the raw data into the boot record structure
            This method should only be called by BootRecord.__init__
            It returns nothing but updates several private attributes of the object
        """
        pass

    @abstractmethod
    def _checkCode(self, rawCode):
        """
            Abstract private helper method that tries to find malicious behaviour in the boot code.
            When something is found, self._suspiciousBehaviour is updated.

        Args:
            rawCode: str of the code section

        Returns: nothing
        """
        pass

    def _matchHash(self, codeHash, expectedLoader):
        """
            Private method that checks if the hash of the boot record's code section is present in the whitelist.
            If a match is found, self._signature is updated with the content of the "Comment" column of the whitelist.
            This method also checks that the whitelist entry matches what was expected from previous processing steps.
            This method updates self._codeHash with the hash of the code section

        Args:
            hash: hashlib.hash object
            expectedLoader: unicode string of the kind of loader that was expected from previous processing or None

        Returns: nothing

        """
        self._codeHash = codeHash.digest()
        # Use the hexdigest for whitelist matching
        hexDigest = codeHash.hexdigest()
        for dictWh in self._whitelist:
            if dictWh['Type'] == self._type and dictWh['SHA256'] == hexDigest:
                self._signature.append(dictWh['Comment'])
                # In addition to signature matching, also check that the loader is what we expected
                if expectedLoader and expectedLoader != dictWh['Comment']:
                    self._suspiciousBehaviour.append('{0} earlier detection expected "{1}" but signature matched "{2}"'
                                                     .format(self._type, expectedLoader, dictWh['Comment']))

    def getDictRecord(self):
        """
            Public method to retrieve a dict of the interesting values of the BootRecord

        Returns: dict

        """
        record = {
            'record_type': self._type,
            'sample_name': self._sample,
            'partition_table': self._partTable,
            'disk_signature': self._diskSignature,
            'oem_id': self._oemId,
            'code_SHA256': self._codeHash,
            'record_raw': self._raw,
            'suspicious_behaviour': self._suspiciousBehaviour,
            'known_code_signature': self._signature,
        }
        return record

    def getRaw(self):
        return self._raw


class MasterBootRecord(BootRecord):
    _MBR_STRUCT = construct.Struct("mbr",
                                   construct.HexDumpAdapter(construct.Bytes("bootloader_code", 440)),
                                   construct.Field('disk_signature', 4),
                                   construct.Padding(2),
                                   construct.Array(4,
                                                   construct.Struct("partitions",
                                                                    construct.SLInt8("state"),
                                                                    construct.BitStruct("beginning",
                                                                                        construct.Octet("head"),
                                                                                        construct.Bits("sect", 6),
                                                                                        construct.Bits("cyl", 10),
                                                                                        ),
                                                                    construct.Enum(construct.UBInt8("type"),
                                                                                   Nothing=0x00,
                                                                                   FAT12=0x01,
                                                                                   XENIX_ROOT=0x02,
                                                                                   XENIX_USR=0x03,
                                                                                   FAT16_old=0x04,
                                                                                   Extended_DOS=0x05,
                                                                                   FAT16=0x06,
                                                                                   FAT32=0x0b,
                                                                                   FAT32_LBA=0x0c,
                                                                                   NTFS=0x07,
                                                                                   LINUX_SWAP=0x82,
                                                                                   LINUX_NATIVE=0x83,
                                                                                   PROTECTIVE_MBR=0xee,
                                                                                   _default_=construct.Pass,
                                                                                   ),
                                                                    construct.BitStruct("ending",
                                                                                        construct.Octet("head"),
                                                                                        construct.Bits("sect", 6),
                                                                                        construct.Bits("cyl", 10),
                                                                                        ),
                                                                    construct.ULInt32("sector_offset"), # offset from MBR in sectors
                                                                    construct.ULInt32("size"),  # in sectors
                                                                    )
                                                   ),
                                   construct.Const(construct.Bytes("signature", 2), '55aa'.decode('hex')),
                                   )

    def __init__(self, filePath, size, offset=None, whitelist=()):
        self._type = 'MBR'
        super(MasterBootRecord, self).__init__(filePath, size, offset, whitelist)

    def _parse(self):
        """
            Main method in charge of parsing the MBR.
            It will try to parse the boot record according to documented known structure and extract the partition table
            disk signature and code section.
            It will then try to narrow down invariant code, hash it and match the hash against a whitelist.
            If no match was found, it will try some simple heuristics to detect malicious behaviours.

        Returns: nothing

        """
        try:
            mbr = self._MBR_STRUCT.parse(self._raw)
        except construct.core.ConstructError as e:
            raise InvalidMBRError('Invalid MBR structure: {0}\n{1}'.format(e, hexdump(self._raw)))

        self._parsePartTable(mbr.partitions)

        # Windows stores the disk signature at 0x1B8, other MBRs seem to leave this area alone
        self._diskSignature = mbr.disk_signature

        # If code section is null, check for protective MBR signature (detected in partition table parsing). If found,
        # then the machine is likely using UEFI instead of BIOS to boot. If not, it could mean that the sample being
        # analyzed has been tampered by a bootkit
        if mbr.bootloader_code.encode('hex') == 440 * '00':
            if 'Protective MBR' in self._signature:
                self._signature.append('UEFI (no legacy boot code)')
            else:
                self._suspiciousBehaviour.append('Code section is null')
        else:
            expectedLoader, invariantCode = self._getInvariantCode(mbr.bootloader_code)
            codeHash = hashlib.sha256(invariantCode)
            self._matchHash(codeHash, expectedLoader)
            if len(self._signature) == 0:
                # No whitelisted signature matched, try some simple heuristics to flag this MBR as malicious
                # Note that the self._checkCode method is only given the "invariant" code section to help with the
                # disassembling. This will obviously leads to broken offsets, but it doesn't matter since the heuristics
                # don't use them.
                self._checkCode(invariantCode)

    def _parsePartTable(self, partitions):
        """
            Private method that parses the partition table of the MBR. Updates self._partTable list.

        Args:
            partitions: Construct.Container object of the partition table

        Returns: nothing
        """
        partNum = 0
        for part in partitions:
            partNum += 1
            # Assume a partition entry without size (in LBA) or type is invalid, and do not include it in the listing.
            if part.size != 0 and part.type != 'Nothing':
                self._partTable.append((partNum, part.state < 0, part.type, part.sector_offset, part.size))
            else:
                self._logger.debug('Ignoring invalid partition: %s', part)
            # Early detection of protective MBR so that we don't try to make sense of the MBR partition table
            if part.type == 'PROTECTIVE_MBR' and partNum == 1:
                self._logger.debug('Protective MBR detected, MBR partition table should not be taken into account. '
                                   'GPT partition table parser not implemented yet')
                self._signature.append('Protective MBR')

    def _getInvariantCode(self, rawCode):
        """
            Helper method that tries to narrow down "invariant code" which can be hashed and compared to well known
            signatures. Most MBRs have localized error strings which must be excluded from the hash computation because
            they may vary from a country to another.
            First, this method tries to detect what kind of MBR it is dealing with. Most of the time, it is enough to
            to look for some known hardcoded strings that identify "well known" MBR (such as Truecrypt, GRUB2, etc...).
            Then, this method finds where the strings are and "removes" them (as in "does not include them").
            Finding these strings can be achieved by quickly studying the assembly code and looking for how these
            strings are echoed on screen at boot time (using interrupt 0x10).
            This research only needs to be done once for each type of MBR but requires an analyst to do it by static
            analysis. This script cannot take care of this. This method merely implements the results of such work.

            Currently supported MBR are:
             - Truecrypt
             - McAfee Endpoint Encryption (Safeboot)
             - GRUB2
             - Windows (XP to 10)

        Args:
            rawCode: str of the code section

        Returns: 2-tuple (unicode string of expected loader, concatenated strings of invariant sections of code)

        """
        # By default, assume all the MBR code section will be hashed. It is obviously wrong in most cases, but it allows
        # for a "default case" which will automatically matches no known hash in case something goes wrong with the
        # detection.
        codeStart = 0
        codeEnd = len(rawCode)
        expectedLoader = None
        invariantCode = str()

        # TrueCrypt (detected with the hardcoded string following the first jump: " TrueCrypt Boot Loader")
        if rawCode[0x5:0x1b].encode('hex').upper() == '2054727565437279707420426F6F74204C6F61646572':
            # TrueCrypt uses hardcoded and not-localized error strings. Therefore every TrueCrypt MBR should have the
            # same code from start to end
            expectedLoader = 'TrueCrypt MBR'

        # MacAfee SafeBoot (detected with the hardcoded string following the first jump: "Safeboot ")
        elif rawCode[0x3:0xc].encode('hex').upper() == '53616665426F6F7420':
            # Two versions have been seen but both start with a jump to the same offset (0x26).
            # There are some strings at the of the code section but localization is unlikely so it will be assumed
            # to be hardcoded (until a localized version is found...).
            # Therefore, Safeboot code can be hashed from 0x26 to the end of code section
            invariantCode += rawCode[:0x3]  # Hash the first JMP
            codeStart = 0x26
            expectedLoader = 'Safeboot MBR'

        # GRUB (detected with the hardcoded string "GRUB " located at 0x188)
        elif rawCode[0x188:0x18d].encode('hex').upper() == '4752554220':
            # GRUB has some error strings but they are hardcoded and not localized so they can be included in the hash
            # computation. However GRUB can be installed on a disk (MBR) as well as on a partition (in a kind of VBR).
            # But in both cases the code used is the same. Since a BPB is needed for the latter case it is also present
            # in the MBR (but not needed). It therefore has to be excluded from the hash computation.
            # GRUB is jumping over the BIOS Parameter Block located between 0x3 and 0x5a.
            # It should be followed by the kernel address (word), kernel sector (dword), kernel sector high (dword) and
            # boot drive (byte). Therefore the code really starts at 0x65.
            # These values are hardcoded in boot.img and have little chance to change anytime soon.
            codeStart = 0x65
            invariantCode += rawCode[:0x3]  # Hash the first JMP
            expectedLoader = 'GRUB2 MBR'

        # Windows MBR cannot be detected with hardcoded strings, so they fall in the default case and further checks
        # are then made based on the hypothesis that this is indeed a Windows MBR.
        else:
            # Starting with NT5.0, the MBR contains localized strings which must be excluded from the hash computation.
            # These strings are located after the code, at 3 different offsets which can be calculated by adding 0x100
            # to the values respectively stored in bytes 0x1b5, 0x1b6 and 0x1b7 (last bytes of the code section).
            # Eg: The first localized string is at : 0x100 + the value saved at offset 0x1B5
            # Even though localized strings can be of different lengths, the offset of the first one does not vary
            # given one Windows version. This can therefore be used to tell Windows versions apart.
            firstStrOffset = construct.UBInt8('FirstStringOffset').parse(rawCode[0x1b5])
            # Windows NT5
            if firstStrOffset == 0x2c:
                expectedLoader = 'NT5.1/NT5.2 MBR'
                codeEnd = 0x100 + firstStrOffset
            # Windows NT6.0
            elif firstStrOffset == 0x62:
                expectedLoader = 'NT6.0 MBR'
                codeEnd = 0x100 + firstStrOffset
            # Windows NT6.1+
            elif firstStrOffset == 0x63:
                expectedLoader = 'NT6.1+ MBR'
                codeEnd = 0x100 + firstStrOffset
            else:
                self._suspiciousBehaviour.append('Invalid string offset: {0:#x}'.format(firstStrOffset))
                self._logger.debug('First localized string offset is wrong for a windows MBR.'
                                   'It should be 0x2c, 0x62 or 0x63) : {0:#x}'.format(firstStrOffset))

        self._logger.debug('Expecting {0}. Code starts at {1:#x} and ends at {2:#x}'
                           .format(expectedLoader, codeStart, codeEnd))

        invariantCode += rawCode[codeStart:codeEnd]
        return expectedLoader, invariantCode

    def _checkCode(self, rawCode):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True

        checkJmp = True
        for i in md.disasm(rawCode, 0):
            # Check for JUMPs and CALLs before the first PUSH/RET.
            if checkJmp and len(i.groups) > 0:
                # Group check if available
                if hasattr(capstone.x86, 'X86_GRP_CALL') and hasattr(capstone.x86, 'X86_GRP_RET'):
                    if capstone.x86.X86_GRP_CALL in i.groups or capstone.x86.X86_GRP_JUMP in i.groups:
                        self._suspiciousBehaviour.append('JMP or CALL before relocation')
                        checkJmp = False
                    elif capstone.x86.X86_GRP_RET in i.groups:
                        # Stop search after the first PUSH/RET
                        checkJmp = False
                # Manual check in case capstone version doesn't support CALL and RET groups
                else:
                    if i.mnemonic[0] == 'j' or i.mnemonic == 'call':
                        self._suspiciousBehaviour.append('JMP or CALL before relocation')
                        checkJmp = False
                    elif i.mnemonic[:3] == 'ret':
                        # Stop search after the first PUSH/RET
                        checkJmp = False

            # Check for unknown interrupt
            if i.mnemonic == 'int' and i.bytes[1] not in (0x10, 0x13, 0x18, 0x1a):
                self._suspiciousBehaviour.append('Unknown Interrupt : {0:#x}'.format(i.bytes[1]))


class VolumeBootRecord(BootRecord):
    _NTFS_VBR_STRUCT = construct.Struct('NTFS-VBR',
                                        construct.Field('JumpOverBPB', 3),
                                        construct.String("OemId", 8),
                                        construct.Struct('BiosParameterBlock',
                                                         construct.ULInt16('SectorSize'),
                                                         construct.ULInt8('SectorsPerCluster'),
                                                         construct.Field('Reserved1', 2),
                                                         construct.Field('MustBeZero1', 3),
                                                         construct.Field('MustBeZero2', 2),
                                                         construct.ULInt8('MediaDescriptor'),
                                                         construct.Field('MustBeZero3', 2),
                                                         construct.ULInt16('SectorsPerTrack'),
                                                         construct.ULInt16('NumberOfHeads'),
                                                         construct.ULInt32('HiddenSectors'),
                                                         construct.Field('NotUsed1', 4),
                                                         construct.Const(construct.Field('DriveNumber', 1),
                                                                         '80'.decode('hex')),
                                                         construct.Field('Reserved2', 3),
                                                         construct.ULInt64('TotalSectors'),
                                                         construct.ULInt64('MFTCluster'),
                                                         construct.ULInt64('MFTMirrCluster'),
                                                         construct.SLInt8('ClustersPerMFTRecord'),
                                                         construct.Field('NotUsed2', 3),
                                                         construct.SLInt8('ClustersPerIdxBuffer'),
                                                         construct.Field('NotUsed3', 3),
                                                         construct.ULInt64('VolumneSN'),
                                                         construct.Field('NotUsed4', 4),
                                                         ),
                                        construct.HexDumpAdapter(construct.Bytes("Code", 426)),
                                        construct.Const(construct.Bytes("signature", 2), '55aa'.decode('hex')),
                                        )

    _BITLOCKER_VBR_STRUCT = construct.Struct('FVE-VBR',
                                             construct.Field('JumpOverBPB', 3),
                                             construct.Const(construct.String("OemId", 8), '-FVE-FS-'.encode('utf8')),
                                             construct.Struct('BiosParameterBlock',
                                                              construct.ULInt16('SectorSize'),
                                                              construct.ULInt8('SectorsPerCluster'),
                                                              construct.Field('Reserved1', 2),
                                                              construct.Field('MustBeZero1', 3),
                                                              construct.Field('MustBeZero2', 2),
                                                              construct.ULInt8('MediaDescriptor'),
                                                              construct.Field('MustBeZero3', 2),
                                                              construct.ULInt16('SectorsPerTrack'),
                                                              construct.ULInt16('NumberOfHeads'),
                                                              construct.ULInt32('HiddenSectors'),
                                                              construct.ULInt32('TotalSectors'),
                                                              construct.ULInt32('SectorsPerFAT'),
                                                              construct.ULInt16('FATFlags'),
                                                              construct.ULInt16('Version'),
                                                              construct.ULInt32('RootDirCluster'),
                                                              construct.ULInt16('FSInfoSector'),
                                                              construct.ULInt16('BackupSector'),
                                                              construct.Field('Reserved2', 12),
                                                              construct.Const(construct.Field('DriveNumber', 1),
                                                                              '80'.decode('hex')),
                                                              construct.Field('Reserved3', 1),
                                                              construct.Field('ExtendedBootSignature', 1),
                                                              construct.ULInt32('VolumneSN'),
                                                              construct.Const(construct.String("VolumeLabel", 11),
                                                                              'NO NAME    '.encode('utf8')),
                                                              construct.Const(construct.String("SystemId", 8),
                                                                              'FAT32   '.encode('utf8')),
                                                              ),
                                             construct.HexDumpAdapter(construct.Bytes("Code1", 70)),
                                             construct.Field('BitlockerGUID', 16),
                                             construct.ULInt64('FVEMetadataBlockOffset1'),
                                             construct.ULInt64('FVEMetadataBlockOffset2'),
                                             construct.ULInt64('FVEMetadataBlockOffset3'),
                                             construct.HexDumpAdapter(construct.Bytes("Code2", 307)),
                                             construct.ULInt8('FirstStrOffset'),
                                             construct.ULInt8('SecondStrOffset'),
                                             construct.ULInt8('ThirdStrOffset'),
                                             construct.Const(construct.Bytes("signature", 2), '55aa'.decode('hex')),
                                             )

    def __init__(self, filePath, size, offset=None, whitelist=()):
        self._type = 'VBR'
        super(VolumeBootRecord, self).__init__(filePath, size, offset, whitelist)

    def _parse(self):
        """
            Main method in charge of parsing the VBR.
            It will try to parse the boot record according to known structures (NTFS and Bitlocker supported).
            It will then try to narrow down invariant code, hash it and match the hash against a whitelist.
            If no match was found, it will try some simple heuristics to detect malicious behaviours.
            Finally it will compare the HiddenSectors value in BPB to that of the record's dump offset.

        Returns: nothing

        """
        try:
            # This will parse both NTFS and Vista bitlocker volumes since they only differ by their OEM ID
            vbr = self._NTFS_VBR_STRUCT.parse(self._raw)
            expectedLoader, invariantCode = self._getInvariantCode('NTFS', vbr)
        except construct.core.ConstructError as e1:
            # Retry with Bitlocker (Win7+) volume header structure
            try:
                vbr = self._BITLOCKER_VBR_STRUCT.parse(self._raw)
                expectedLoader, invariantCode = self._getInvariantCode('bitlocker', vbr)
            except construct.core.ConstructError as e2:
                raise InvalidVBRError('Invalid VBR structure: e1={0}, e2={1}\n{2}'.format(e1, e2, hexdump(self._raw)))

        self._oemId = vbr.OemId
        self._bpb = vbr.BiosParameterBlock
        codeHash = hashlib.sha256(invariantCode)
        self._matchHash(codeHash, expectedLoader)

        # If no whitelisted signature matched, try some simple heuristics to flag this VBR as malicious
        # Note that the self._checkCode method is only given the "invariant" code section to help with the
        # disassembling. This will obviously leads to broken offsets, but it doesn't matter since the heuristics don't
        # use them.
        if len(self._signature) == 0:
            self._checkCode(invariantCode)

        # At last, compare the offset at which this VBR was found with the value of the BPB HiddenSectors
        if self._offset is not None \
                and (vbr.BiosParameterBlock.HiddenSectors * vbr.BiosParameterBlock.SectorSize) != self._offset:
            self._suspiciousBehaviour.append(
                'Suspicious HiddenSectors value: {0} ({1} bytes)'
                .format(vbr.BiosParameterBlock.HiddenSectors,
                        vbr.BiosParameterBlock.HiddenSectors * vbr.BiosParameterBlock.SectorSize))

    def _getInvariantCode(self, vbrType, vbrStruct):
        """
            Helper method that finds all the sections of the boot code that can be hashed and compared to a whitelist.
            This means that localized strings and other variable parameters (BPB, etc...) are excluded.
            Currently, this method only supports NTFS and Bitlocker VBR.

        Args:
            vbrType: unicode string corresponding to the VBR type ('NTFS' or 'bitlocker')
            vbrStruct: construct.container of the VBR

        Returns: 2-tuple (unicode string of expected loader, concatenated strings of invariant sections of code)

        """
        codeStart = 0
        codeEnd = None
        invariantCode = str()
        expectedLoader = None

        if vbrType == 'NTFS':
            # The first three bytes are a jump over the NTFS BPB to where the code really starts (0x54) and a NOP
            invariantCode += vbrStruct.JumpOverBPB
            codeStart = 0x54
            # NTFS VBR contains localized strings which must be excluded from the hash computation.
            # Before Windows 8, these strings are located at 4 different offsets which can be calculated by adding
            # 0x100 to the values respectively stored in bytes 0x1f8, 0x1f9, 0x1fa and 0x1fb.
            # Starting from Windows 8, these strings are located at 3 different offsets which are directly stored in
            # little endian words respectively at 0x1f6, 0x1f8 and 0x1fa
            # Since there is no easy way to tell which version of Windows we are dealing with beforehand, we first
            # assume it is a Windows < 8 by testing 0x1f8 against all the known first offset. If all tests fail, assume
            # it is Windows >= 8 and check 0x1f6 against the only known first offset (to date)
            firstStrOffset = construct.UBInt8('FirstStringOffset').parse(self._raw[0x1f8])
            # Windows NT5
            if firstStrOffset == 0x83:
                expectedLoader = 'NT5.1/NT5.2 VBR'
                codeEnd = 0x100 + firstStrOffset
            # Windows NT6.0
            elif firstStrOffset == 0x80:
                expectedLoader = 'NT6.0 VBR'
                codeEnd = 0x100 + firstStrOffset
            # Windows NT6.1
            elif firstStrOffset == 0x8c:
                expectedLoader = 'NT6.1 VBR'
                codeEnd = 0x100 + firstStrOffset
            # Windows NT6.2+
            else:
                firstStrOffset = construct.ULInt16('FirstStringOffset').parse(self._raw[0x1f6:0x1f8])
                if firstStrOffset == 0x18a:
                    expectedLoader = 'NT6.2+ VBR'
                    codeEnd = firstStrOffset

            if codeEnd is None:
                self._suspiciousBehaviour.append('Invalid string offset: {0:#x}'.format(firstStrOffset))
                self._logger.debug('First localized string offset is wrong for a NTFS VBR: {0:#x}. '
                                   'It should be 0x83, 0x80, 0x8c or 0x18a.'.format(firstStrOffset))
                codeEnd = 0

        elif vbrType == 'bitlocker':
            expectedLoader = 'NT6.1+ Bitlocker VBR'
            # The first three bytes are a jump over the NTFS BPB to where the code really starts (0x5A) and a NOP
            invariantCode += vbrStruct.JumpOverBPB
            # First section of code (_BITLOCKER_VBR_STRUCT.Code1)
            invariantCode += vbrStruct.Code1
            # In the second section of code, there are localized strings which must be excluded from hash computation.
            # Their offsets are stored in the last 3 bytes before the VBR signature (0x55aa).
            # For Windows 8, 8.1 and 10, the first string offset seems to always be 0x100 (ie. FirstStrOffset = 0x00)
            if vbrStruct.FirstStrOffset != 0:
                self._suspiciousBehaviour.append('Invalid string offset: {0:#x}'.format(vbrStruct.FirstStrOffset))
                self._logger.debug('First localized string offset is wrong for a Bitlocker VBR. '
                                   'It should be 0x00) : {0:#x}'.format(vbrStruct.FirstStrOffset))
            codeStart = 0xc8  # Offset of Code2
            codeEnd = 0x100 + vbrStruct.FirstStrOffset
        else:
            raise NotImplementedError('VBR type "{0}" is not implemented yet'.format(vbrType))

        self._logger.debug('Expecting {0}. Code starts at {1:#x} and ends at {2:#x}'
                           .format(expectedLoader, codeStart, codeEnd))

        invariantCode += self._raw[codeStart:codeEnd]
        return expectedLoader, invariantCode

    def _checkCode(self, code):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True
        for i in md.disasm(code, 0):
            # Check for unknown interrupt
            if i.mnemonic == 'int' and i.bytes[1] not in (0x10, 0x13, 0x18, 0x1a):
                self._suspiciousBehaviour.append('Unknown Interrupt : {0:#x}'.format(i.bytes[1]))


class InitialProgramLoader(BootRecord):
    _IPL_HEADER = construct.Struct('IPL_HEADER',
                                   construct.ULInt16('sig_len'),
                                   construct.String('signature', length=lambda ctx: ctx.sig_len * 2,
                                                    encoding='utf16'.encode('utf8')))

    def __init__(self, filePath, size, offset=None, whitelist=()):
        self._type = 'IPL'
        super(InitialProgramLoader, self).__init__(filePath, size, offset, whitelist)

    def _parse(self):
        try:
            header = self._IPL_HEADER.parse(self._raw)
        except (construct.ConstructError, UnicodeDecodeError) as e:
            raise InvalidIPLError('Invalid IPL structure: {0}\n{1}'.format(e, hexdump(self._raw[:0x200])))

        try:
            # IPL's code section is usually contained is the first 9 sectors. The remaining sectors are filled with
            # padding but it appears that the last (15th) sector can sometimes hold data not related to the boot process
            # and we need to exclude that from hash calculation.
            invariantCode = self._raw[:14*512]
        except IndexError:
            raise InvalidIPLError('Invalid sample size for IPL: {0} (should be 15 * 512-bytes sectors)'
                                  .format(len(self._raw)))

        expectedLoader = None

        # Starting with NT 6.2, IPL has a localized string that must be excluded from hash computation.
        # The difference between these two kinds of IPL can be told from the instruction located at 0x56 :
        # a Jump Short (EB) in case of IPL<6.2 or a Jump Near (E9) otherwise
        if header.signature == 'BOOTMGR' and self._raw[0x56].encode('hex').upper() == 'E9':
            # The offset of the localized string seems to be stored in a DWORD at 0x117 (just before the beginning
            # of the assembly code). But the value seems to be an offset relative to the start of the whole
            # boot record (including the VBR) and not just the IPL.
            # Therefore we need to substract 0x200 to get the offset inside the IPL.
            strOffset = construct.ULInt16('offset').parse(self._raw[0x117:]) - 0x200
            # Exclude from hash calculation everything between the string offset and the beginning of code
            invariantCode = invariantCode[:strOffset] + invariantCode[0x119:]
            expectedLoader = 'NT6.2+ IPL'

        codeHash = hashlib.sha256(invariantCode)
        self._matchHash(codeHash, expectedLoader)

        # If no whitelisted signature matched, try some simple heuristics to flag this IPL as malicious
        # Note that the self._checkCode method is only given the "stripped" code section to help the disassembling.
        # This will obviously leads to broken offsets, but it doesn't matter since the heuristics don't use them.
        if len(self._signature) == 0:
            self._checkCode(invariantCode)

    def _checkCode(self, code):
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
        md.detail = True
        for i in md.disasm(code, 0):
            # Check for unknown interrupt
            if i.mnemonic == 'int' and i.bytes[1] not in (0x10, 0x13, 0x18, 0x1a):
                self._suspiciousBehaviour.append('Unknown Interrupt : {0:#x}'.format(i.bytes[1]))


class InvalidBootRecordError(Exception):
    pass


class InvalidMBRError(InvalidBootRecordError):
    pass


class InvalidVBRError(InvalidBootRecordError):
    pass


class InvalidIPLError(InvalidBootRecordError):
    pass


def hexdump(src, length=16, sep='.'):
    """
    @brief Return {src} in hex dump.
    @param[in] length       {Int} Nb Bytes by row.
    @param[in] sep          {Char} For the text part, {sep} will be used for non ASCII char.
    @return {Str} The hexdump

    @note Code borrowed from https://gist.github.com/ImmortalPC/c340564823f283fe530b
    """
    result = []

    # Python3 support
    try:
        xrange(0, 1)
    except NameError:
        xrange = range

    for i in xrange(0, len(src), length):
        subSrc = src[i:i + length]
        hexa = ''
        isMiddle = False
        for h in xrange(0, len(subSrc)):
            if h == length / 2:
                hexa += ' '
            h = subSrc[h]
            if not isinstance(h, int):
                h = ord(h)
            h = hex(h).replace('0x', '')
            if len(h) == 1:
                h = '0' + h
            hexa += h + ' '
        hexa = hexa.strip(' ')
        text = ''
        for c in subSrc:
            if not isinstance(c, int):
                c = ord(c)
            if 0x20 <= c < 0x7F:
                text += chr(c)
            else:
                text += sep
        result.append(('%08X:  %-' + str(length * (2 + 1) + 1) + 's  |%s|') % (i, hexa, text))

    return '\n'.join(result)


def initWhitelist(fWhitelist):
    whitelist = []
    # CSV file content should be "Type,SHA256,Comment"
    with open(fWhitelist, 'rb') as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            whitelist.append(row)
    return whitelist


def checkResult(objBr, brType):
    """
    Simple function to check if anything is suspicious in the BootRecord

    :param objBr: BootRecord object
    :param brType: unicode string, type of BootRecord (MBR, VBR or IPL)
    :return: boolean, True if everything is OK, False otherwise
    """
    logger.extra.update({'stage': brType})
    ret = True
    if getattr(objBr, '_signature', None):
        logger.info('Known signatures found: %r',  getattr(objBr, '_signature'))
    else:
        ret = False
        logger.warning('No known code signature were found, this is highly suspicious.')
        if getattr(objBr, '_codeHash'):
            logger.debug('Sample\'s code hash is: %r', getattr(objBr, '_codeHash').encode('hex'))
    if getattr(objBr, '_suspiciousBehaviour'):
        ret = False
        logger.warning('Suspicious behaviours were detected: %r', getattr(objBr, '_suspiciousBehaviour'))
    return ret


def parseBootRecord(brType, input, offset, whitelist):
    logger.extra.update({'stage': brType})
    try:
        if brType == 'MBR':
            objBr = MasterBootRecord(input, 512, whitelist=whitelist)
        elif brType == 'VBR':
            objBr = VolumeBootRecord(input, 512, offset=offset, whitelist=whitelist)
        elif brType == 'IPL':
            objBr = InitialProgramLoader(input, 15*512, whitelist=whitelist)
        else:
            return
        checkResult(objBr, brType)
    except InvalidBootRecordError as e:
        logger.error(e)
        return


def parseImageFile(input, sectorSize, whitelist):
    try:
        objMBR = MasterBootRecord(input, sectorSize, 0, whitelist)
        checkResult(objMBR, 'MBR')
        activePart = []
        for part in getattr(objMBR, '_partTable'):
            # A partition is a tuple: (number, state, type, sector_offset, size)
            if part[1]:
                activePart = part
                # The first active partition is the one the MBR will load the VBR from
                break
        logger.extra.update({'stage': 'IMG'})
        if activePart:
            logger.debug('Found active partition n°%d starting at sector %d', activePart[0], activePart[3])
            offset = activePart[3]*sectorSize
            input.seek(offset)
            objVBR = VolumeBootRecord(input, sectorSize, offset=offset, whitelist=whitelist)
            if not checkResult(objVBR, 'VBR'):
                logger.warning('VBR of the active partition located at sector %d (offset %d) is suspicious (see '
                               'previous warning). This could mean that the partition table in the MBR or the BPB in '
                               'the VBR has been tampered with !', activePart[3], offset)
            hiddenSectors = getattr(objVBR, '_bpb').HiddenSectors
            logger.extra.update({'stage': 'IMG'})
            logger.debug('Found HiddenSectors value: %d', hiddenSectors)
            if hiddenSectors != (offset / sectorSize):
                logger.warning('HiddenSectors value in BiosParameterBlock is different than actual offset in partition '
                               'table ! HiddenSectors=%d, partition table offset=%d', hiddenSectors, offset/sectorSize)
            # IPL is just next to the VBR. Even when sectors are 4KB in size, the VBR and IPL will be contiguous : there
            # is no "slack space" between the VBR and IPL. Therefore, IPL will always be located at VBR offset + 512
            input.seek((hiddenSectors * sectorSize) + 512)
            objIPL = InitialProgramLoader(input, 15 * sectorSize, whitelist=whitelist)
            checkResult(objIPL, 'IPL')
        else:
            logger.warning('No active partition detected in MBR !')
    except InvalidBootRecordError as e:
        logger.error(e)


if __name__ == '__main__':
    import argparse
    global logger

    parser = argparse.ArgumentParser(description='Check boot records for known good signatures',
                                     formatter_class=argparse.RawTextHelpFormatter,
                                     add_help=True)
    parser.add_argument('--type', choices=['VBR', 'MBR', 'IPL', 'IMG'], required=True,
                        type=lambda x: x.decode(sys.getfilesystemencoding()).upper(),
                        help='Type of boot record: MBR, VBR or IPL. Or whole disk image.')
    parser.add_argument('--input', required=True, type=lambda x: x.decode(sys.getfilesystemencoding()), nargs='+',
                        help='Input file(s) to check')
    parser.add_argument('--offset', type=int,
                        help='Offset in bytes at which the boot record was dumped. Required only for VBR. Without it, '
                             'some heuristics to detect malicious VBR will not work.')
    # Note that when using native 4K disks, Windows can only be installed in UEFI. Support for 4K sectors in this script
    # is mostly for testing purpose since no "default" Windows installation can ever be found on native 4K disks.
    # However, this option can be used to test a non-booting native 4K disk/volume.
    parser.add_argument('--sector-size', type=int, default=512,
                        help='Disk sector size in bytes. Only applies for disk image input. Defaults to 512.')
    parser.add_argument('--whitelist', help='CSV file containing whitelisted boot record signatures. '
                                            'Without it, the boot record will always be flagged as suspicious. '
                                            'Defaults to {0}'.format(BOOTRECORD_WHITELIST_PATH),
                        default=BOOTRECORD_WHITELIST_PATH, type=lambda x: x.decode(sys.getfilesystemencoding()))
    parser.add_argument('--logLevel', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Show debug messages according to the level provided.')
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.logLevel.upper()),
                        format='%(levelname)-8s - [%(objectid)s] [%(stage)s] %(message)s')
    logger = logging.LoggerAdapter(logging.getLogger(__file__), {'objectid': None, 'stage': 'main'})

    if args.type == 'VBR' and args.offset is None:
        logger.error('--offset is required when parsing VBR')
        sys.exit(1)

    if args.whitelist is not None:
        whitelist = initWhitelist(args.whitelist)
    else:
        whitelist = []

    for inputFile in args.input:
        logger.extra.update({'objectid': inputFile})
        with open(inputFile, 'rb') as f_input:
            if args.type == 'IMG':
                logger.debug('Parsing disk image file %s with %d whitelisted records', args.input, len(whitelist))
                parseImageFile(f_input, args.sector_size, whitelist)
            else:
                logger.debug('%s dumped %swith %d whitelisted records', args.type,
                             'at offset {0} '.format(args.offset) if args.offset else '',
                             len(whitelist))
                parseBootRecord(args.type, f_input, args.offset, whitelist)

# This is only useful for pytest
logger = logging.LoggerAdapter(logging.getLogger(__file__), {'objectid': None, 'stage': 'main'})
