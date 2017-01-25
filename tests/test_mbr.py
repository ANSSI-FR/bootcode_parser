#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from bootcode_parser import MasterBootRecord, InvalidMBRError
import os
import pytest


def test_mbr_nt5_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_5.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'MBR',
        'sample_name': sampleName,
        'partition_table': [(1, True, 'NTFS', 63, 73368792)],
        'disk_signature': '059c059c'.decode('hex'),
        'oem_id': None,
        'code_SHA256': 'b5ed343494f0326a08aa6abf7cc9aa4d96207532cf0d2b39453c6eb7bede19e3'.decode('hex'),
        'record_raw': '33c08ed0bc007cfb5007501ffcbe1b7cbf1b065057b9e501f3a4cbbdbe07b104386e007c09751383c510e2f4cd188bf5'
                      '83c610497419382c74f6a0b507b4078bf0ac3c0074fcbb0700b40ecd10ebf2884e10e84600732afe4610807e040b740b'
                      '807e040c7405a0b60775d2804602068346080683560a00e821007305a0b607ebbc813efe7d55aa740b807e100074c8a0'
                      'b707eba98bfc1e578bf5cbbf05008a5600b408cd1372238ac1243f988ade8afc43f7e38bd186d6b106d2ee42f7e23956'
                      '0a77237205394608731cb80102bb007c8b4e028b5600cd1373514f744e32e48a5600cd13ebe48a560060bbaa55b441cd'
                      '13723681fb55aa7530f6c101742b61606a006a00ff760aff76086a0068007c6a016a10b4428bf4cd136161730e4f740b'
                      '32e48a5600cd13ebd661f9c35461626c6520646520706172746974696f6e206e6f6e2076616c69646500457272657572'
                      '206c6f7273206475206368617267656d656e7420647520737973748a6d652064276578706c6f69746174690053797374'
                      '8a6d652064276578706c6f69746174696f6e20616273656e740000000000000000000000000000000000000000000000'
                      '00000000002c4a7c059c059c00008001010007feffff3f000000d8845f04000000000000000000000000000000000000'
                      '00000000000000000000000000000000000000000000000000000000000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT5.1/NT5.2 MBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objMBR = MasterBootRecord(f_mbr, os.path.getsize(f_mbr.name), whitelist=whitelist)
        dParsed = objMBR.getDictRecord()
    assert dParsed == dExpected


def test_mbr_nt60_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_60.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'MBR',
        'sample_name': sampleName,
        'partition_table': [(1, True, 'NTFS', 2048, 41938944)],
        'disk_signature': 'c9eda2df'.decode('hex'),
        'oem_id': None,
        'code_SHA256': '4799e8c92d32bca8e5103110a322523adb7a3909324132bd9abab8f3345e094a'.decode('hex'),
        'record_raw': '33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfbb90400bdbe07807e00007c0b0f85100183c510'
                      'e2f1cd1888560055c6461105c6461000b441bbaa55cd135d720f81fb55aa7509f7c101007403fe46106660807e100074'
                      '2666680000000066ff760868000068007c680100681000b4428a56008bf4cd139f83c4109eeb14b80102bb007c8a5600'
                      '8a76018a4e028a6e03cd136661731efe4e110f850c00807e00800f848a00b280eb825532e48a5600cd135deb9c813efe'
                      '7d55aa756eff7600e88a000f851500b0d1e664e87f00b0dfe660e87800b0ffe664e87100b800bbcd1a6623c0753b6681'
                      'fb54435041753281f90201722c666807bb00006668000200006668080000006653665366556668000000006668007c00'
                      '00666168000007cd1a5a32f6ea007c0000cd18a0b707eb08a0b607eb03a0b50732e40500078bf0ac3c0074fcbb0700b4'
                      '0ecd10ebf22bc9e464eb002402e0f82402c3496e76616c696420706172746974696f6e207461626c65004572726f7220'
                      '6c6f6164696e67206f7065726174696e672073797374656d004d697373696e67206f7065726174696e67207379737465'
                      '6d00000000627a99c9eda2df00008020210007feffff0008000000f07f02000000000000000000000000000000000000'
                      '00000000000000000000000000000000000000000000000000000000000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.0 MBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objMBR = MasterBootRecord(f_mbr, os.path.getsize(f_mbr.name), whitelist=whitelist)
        dParsed = objMBR.getDictRecord()
    assert dParsed == dExpected


def test_mbr_nt61_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_61.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'MBR',
        'sample_name': sampleName,
        'partition_table': [(1, True, 'NTFS', 2048, 204800),
                            (2, False, 'NTFS', 206848, 40685568),
                            (3, False, 'NTFS', 40892416, 1046528)],
        'disk_signature': '14a90642'.decode('hex'),
        'oem_id': None,
        'code_SHA256': '088995559ab317af9b3291408da689651e8353f62e0a478d92eb0b5a947063fd'.decode('hex'),
        'record_raw': '33c08ed0bc007c8ec08ed8be007cbf0006b90002fcf3a450681c06cbfbb90400bdbe07807e00007c0b0f850e0183c510'
                      'e2f1cd1888560055c6461105c6461000b441bbaa55cd135d720f81fb55aa7509f7c101007403fe46106660807e100074'
                      '2666680000000066ff760868000068007c680100681000b4428a56008bf4cd139f83c4109eeb14b80102bb007c8a5600'
                      '8a76018a4e028a6e03cd136661731cfe4e11750c807e00800f848a00b280eb845532e48a5600cd135deb9e813efe7d55'
                      'aa756eff7600e88d007517fab0d1e664e88300b0dfe660e87c00b0ffe664e87500fbb800bbcd1a6623c0753b6681fb54'
                      '435041753281f90201722c666807bb00006668000200006668080000006653665366556668000000006668007c000066'
                      '6168000007cd1a5a32f6ea007c0000cd18a0b707eb08a0b607eb03a0b50732e40500078bf0ac3c007409bb0700b40ecd'
                      '10ebf2f4ebfd2bc9e464eb002402e0f82402c3496e76616c696420706172746974696f6e207461626c65004572726f72'
                      '206c6f6164696e67206f7065726174696e672073797374656d004d697373696e67206f7065726174696e672073797374'
                      '656d000000637b9a14a9064200008020210007df130c000800000020030000df140c07feffff0028030000d06c0200fe'
                      'ffff07feffff00f86f0200f80f000000000000000000000000000000000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.1+ MBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objMBR = MasterBootRecord(f_mbr, os.path.getsize(f_mbr.name), whitelist=whitelist)
        dParsed = objMBR.getDictRecord()
    assert dParsed == dExpected


def test_mbr_empty_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_empty.bin')

    with pytest.raises(InvalidMBRError) as e:
        with open(sampleName, 'rb') as f_mbr:
            objMBR = MasterBootRecord(f_mbr, os.path.getsize(f_mbr.name), whitelist=whitelist)
    assert "Invalid MBR structure: expected " in str(e.value)


def test_mbr_empty_code_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_empty_code.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'MBR',
        'sample_name': sampleName,
        'partition_table': [(1, True, 'NTFS', 2048, 204800),
                            (2, False, 'NTFS', 206848, 40685568),
                            (3, False, 'NTFS', 40892416, 1046528)],
        'disk_signature': '14a90642'.decode('hex'),
        'oem_id': None,
        'code_SHA256': None,
        'record_raw': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000014a9064200008020210007df130c000800000020030000df140c07feffff0028030000d06c0200fe'
                      'ffff07feffff00f86f0200f80f000000000000000000000000000000000055aa'.decode('hex'),
        'suspicious_behaviour': ['Code section is null'],
        'known_code_signature': [],
    }
    with open(sampleName, 'rb') as f_mbr:
        objMBR = MasterBootRecord(f_mbr, os.path.getsize(f_mbr.name), whitelist=whitelist)
        dParsed = objMBR.getDictRecord()
    assert dParsed == dExpected


def test_mbr_tc_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_tc.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'MBR',
        'sample_name': sampleName,
        'partition_table': [(1, True, 'NTFS', 2048, 204800),
                            (2, False, 'NTFS', 206848, 40685568),
                            (3, False, 'NTFS', 40892416, 1046528)],
        'disk_signature': 'c9a7ee57'.decode('hex'),
        'oem_id': None,
        'code_SHA256': 'e6e6605c48665800786de4651ade2893970aafb1237a06db0943a8603dd4fce1'.decode('hex'),
        'record_raw': 'ea1e7c00002054727565437279707420426f6f74204c6f616465720d0a00fa33c08ed88ed0bc007cfbf606b67d017507'
                      '8d36057ce8dc00b80090813e13045c027d0eb80088813e13043c027d03b800208ec032c0bf0001b9ff6efcf3aa8cc02d'
                      '00088ec0b102b004bb0001e8b4006633dbbe0001b90008e8ba006653bb000db106b039f606467d017404b01ab124e891'
                      '00665bbe000d8b0eb07de89700663b1eb27d7425f606467d01750ec606467d01b120f606b77d0275ad8d36557de85300'
                      '8d36057ce84c00ebfe8cc08ed8fa8ed0bc0080fb52680a0d68007a6800810e68e77c06680001cb83c4065a0e1f85c074'
                      '098d36557de81b00ebfe8a36b77d8cc00500088ec08ed8fa8ed0bcfc6ffb06680001cb33dbb40efcac84c07404cd10eb'
                      'f7c3b500b600b402cd1373078d36477de8e0ffc31e061f6633c0fcac6603d866d1c3e2f71fc3004469736b206572726f'
                      '720d0a0700074c6f616465722064616d61676564212055736520526573637565204469736b3a20526570616972204f70'
                      '74696f6e73203e20526573746f726500000000000000000000000000000000000000000000000000000000000000071a'
                      '722e832e05b50006c9a7ee5700008020210007df130c000800000020030000df140c07feffff0028030000d06c0200fe'
                      'ffff07feffff00f86f0200f80f000000000000000000000000000000000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['TrueCrypt MBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objMBR = MasterBootRecord(f_mbr, os.path.getsize(f_mbr.name), whitelist=whitelist)
        dParsed = objMBR.getDictRecord()
    assert dParsed == dExpected

def test_mbr_uefi_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_protect_uefi.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'MBR',
        'sample_name': sampleName,
        'partition_table': [(1, False, 'PROTECTIVE_MBR', 1, 41943039)],
        'disk_signature': '00000000'.decode('hex'),
        'oem_id': None,
        'code_SHA256': None,
        'record_raw': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000100eefeffff01000000ffff7f02000000000000000000000000000000000000'
                      '00000000000000000000000000000000000000000000000000000000000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['Protective MBR', 'UEFI (no legacy boot code)'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objMBR = MasterBootRecord(f_mbr, os.path.getsize(f_mbr.name), whitelist=whitelist)
        dParsed = objMBR.getDictRecord()
    assert dParsed == dExpected
