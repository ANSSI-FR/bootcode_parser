#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from bootcode_parser import VolumeBootRecord, InvalidVBRError
import os
import pytest


def test_vbr_nt5_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'vbr_5_off_32256.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'VBR',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': 'NTFS    ',
        'code_SHA256': '5cb5aa385e0ada266690a2821e3a36ad372720d2ff47c0b1cd9d6ebcab25bf4e'.decode('hex'),
        'record_raw': 'eb52904e5446532020202000020800000000000000f800003f00ff003f0000000000000080008000d7845f0400000000'
                      '00000c00000000004df8450000000000f6000000010000000e11dfc051dfc0bc00000000fa33c08ed0bc007cfbb8c007'
                      '8ed8e81600b8000d8ec033dbc6060e0010e8530068000d686a02cb8a162400b408cd137305b9ffff8af1660fb6c64066'
                      '0fb6d180e23ff7e286cdc0ed0641660fb7c966f7e166a32000c3b441bbaa558a162400cd13720f81fb55aa7509f6c101'
                      '7404fe061400c366601e0666a110006603061c00663b0620000f823a001e666a0066500653666810000100803e140000'
                      '0f850c00e8b3ff803e1400000f846100b4428a162400161f8bf4cd1366585b07665866581feb2d6633d2660fb70e1800'
                      '66f7f1fec28aca668bd066c1ea10f7361a0086d68a1624008ae8c0e4060accb80102cd130f8219008cc00520008ec066'
                      'ff061000ff0e0e000f856fff071f6661c3a0f801e80900a0fb01e80300fbebfeb4018bf0ac3c007409b40ebb0700cd10'
                      'ebf2c30d0a4572722e206c65637475726520646973717565000d0a4e544c4452206d616e717565000d0a4e544c445220'
                      '65737420636f6d707265737382000d0a456e7472657a204374726c2b416c742b537570707220706f757220726564826d'
                      '61727265720d0a000d0a00000000000000000000000000008399a8be000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT5.1/NT5.2 VBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objVBR = VolumeBootRecord(f_mbr, os.path.getsize(f_mbr.name), offset=32256, whitelist=whitelist)
        dParsed = objVBR.getDictRecord()
    assert dParsed == dExpected


def test_vbr_nt60_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'vbr_60_off_1048576.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'VBR',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': 'NTFS    ',
        'code_SHA256': 'a1932aaba7d6d3adb1637e2ee0c8355706842ba825ea811728165420c518c0b1'.decode('hex'),
        'record_raw': 'eb52904e5446532020202000020800000000000000f800003f00ff00000800000000000080008000ffefdf0100000000'
                      '00000c0000000000fffe1d0000000000f600000001000000acbf151cf6151c2800000000fa33c08ed0bc007cfb68c007'
                      '1f1e686600cb88160e0066813e03004e5446537515b441bbaa55cd13720c81fb55aa7506f7c101007503e9d2001e83ec'
                      '18681a00b4488a160e008bf4161fcd139f83c4189e581f72e13b060b0075dba30f00c12e0f00041e5a33dbb900202bc8'
                      '66ff06110003160f008ec2ff061600e840002bc877efb800bbcd1a6623c0752d6681fb54435041752481f90201721e16'
                      '6807bb1668700e1668090066536653665516161668b80166610e07cd1ae96a01909066601e0666a111006603061c001e'
                      '66680000000066500653680100681000b4428a160e00161f8bf4cd1366595b5a665966591f0f82160066ff0611000316'
                      '0f008ec2ff0e160075bc071f6661c3a0f801e80800a0fb01e80200ebfeb4018bf0ac3c007409b40ebb0700cd10ebf2c3'
                      '0d0a41206469736b2072656164206572726f72206f63637572726564000d0a424f4f544d4752206973206d697373696e'
                      '67000d0a424f4f544d475220697320636f6d70726573736564000d0a5072657373204374726c2b416c742b44656c2074'
                      '6f20726573746172740d0a00000000000000000000000000809db2ca000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.0 VBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objVBR = VolumeBootRecord(f_mbr, os.path.getsize(f_mbr.name), offset=1048576, whitelist=whitelist)
        dParsed = objVBR.getDictRecord()
    assert dParsed == dExpected


def test_vbr_nt61_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'vbr_61_off_1048576.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'VBR',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': 'NTFS    ',
        'code_SHA256': '96d38c1be37b9124fb71d1d0f5c52969f0074687fe17aef0e1bafc54428674f6'.decode('hex'),
        'record_raw': 'eb52904e5446532020202000020800000000000000f800003f00ff00000800000000000080008000ff1f030000000000'
                      '55210000000000000200000000000000f6000000010000003231dc285edc286400000000fa33c08ed0bc007cfb68c007'
                      '1f1e686600cb88160e0066813e03004e5446537515b441bbaa55cd13720c81fb55aa7506f7c101007503e9dd001e83ec'
                      '18681a00b4488a160e008bf4161fcd139f83c4189e581f72e13b060b0075dba30f00c12e0f00041e5a33dbb900202bc8'
                      '66ff06110003160f008ec2ff061600e84b002bc877efb800bbcd1a6623c0752d6681fb54435041752481f90201721e16'
                      '6807bb1668700e1668090066536653665516161668b80166610e07cd1a33c0bf2810b9d80ffcf3aae95f01909066601e'
                      '0666a111006603061c001e66680000000066500653680100681000b4428a160e00161f8bf4cd1366595b5a665966591f'
                      '0f82160066ff06110003160f008ec2ff0e160075bc071f6661c3a0f801e80900a0fb01e80300f4ebfdb4018bf0ac3c00'
                      '7409b40ebb0700cd10ebf2c30d0a41206469736b2072656164206572726f72206f63637572726564000d0a424f4f544d'
                      '4752206973206d697373696e67000d0a424f4f544d475220697320636f6d70726573736564000d0a5072657373204374'
                      '726c2b416c742b44656c20746f20726573746172740d0a008ca9bed6000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.1 VBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objVBR = VolumeBootRecord(f_mbr, os.path.getsize(f_mbr.name), offset=1048576, whitelist=whitelist)
        dParsed = objVBR.getDictRecord()
    assert dParsed == dExpected


def test_vbr_nt61_bitlocker_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'vbr_61_bitlocker_off_525336576.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'VBR',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': '-FVE-FS-',
        'code_SHA256': '47138cbe995a20483209270ef55693c8c8e85ca870f28789229ce421aded92b4'.decode('hex'),
        'record_raw': 'eb58902d4656452d46532d00020800000000000000f800003f00ff0000a80f0000000000e01f00000000000000000000'
                      '01000600000000000000000000000000800029000000004e4f204e414d4520202020464154333220202033c98ed1bcf4'
                      '7b8ec18ed9bd007ca0fb7db47d8bf0ac9840740c48740eb40ebb0700cd10ebefa0fd7debe6cd16cd1900000000000000'
                      '000000000000000000000000000000003bd66749292ed84a8399f6a339e3d0010060cb0f000000000000504900000000'
                      '008024bc0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000d0a52656d6f7665206469736b73206f72206f74686572206d656469612eff0d'
                      '0a4469736b206572726f72ff0d0a507265737320616e79206b657920746f20726573746172740d0a0000000000000000'
                      '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
                      '000000000000000000000000000000000000000000000000787878787878787878787878787878787878787878787878'
                      '787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878'
                      '7878787878787878ffffffffffffffffffffffffffffffffffffff001f2c55aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.1+ Bitlocker VBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objVBR = VolumeBootRecord(f_mbr, os.path.getsize(f_mbr.name), offset=525336576, whitelist=whitelist)
        dParsed = objVBR.getDictRecord()
    assert dParsed == dExpected


def test_vbr_nt62_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'vbr_62_off_1048576.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'VBR',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': 'NTFS    ',
        'code_SHA256': '51643dcce7e93d795b08e1f19e38374ae4deaf3b1217527561a44aa9913ded23'.decode('hex'),
        'record_raw': 'eb52904e5446532020202000020800000000000000f800003f00ff00000800000000000080008000ff0f0e0000000000'
                      '00960000000000000200000000000000f600000001000000f8c2981acf981a4000000000fa33c08ed0bc007cfb68c007'
                      '1f1e686600cb88160e0066813e03004e5446537515b441bbaa55cd13720c81fb55aa7506f7c101007503e9dd001e83ec'
                      '18681a00b4488a160e008bf4161fcd139f83c4189e581f72e13b060b0075dba30f00c12e0f00041e5a33dbb900202bc8'
                      '66ff06110003160f008ec2ff061600e84b002bc877efb800bbcd1a6623c0752d6681fb54435041752481f90201721e16'
                      '6807bb166852111668090066536653665516161668b80166610e07cd1a33c0bf0a13b9f60cfcf3aae9fe01909066601e'
                      '0666a111006603061c001e66680000000066500653680100681000b4428a160e00161f8bf4cd1366595b5a665966591f'
                      '0f82160066ff06110003160f008ec2ff0e160075bc071f6661c3a1f601e80900a1fa01e80300f4ebfd8bf0ac3c007409'
                      'b40ebb0700cd10ebf2c30d0a41206469736b2072656164206572726f72206f63637572726564000d0a424f4f544d4752'
                      '20697320636f6d70726573736564000d0a5072657373204374726c2b416c742b44656c20746f20726573746172740d0a'
                      '000000000000000000000000000000000000000000008a01a701bf01000055aa'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.2+ VBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objVBR = VolumeBootRecord(f_mbr, os.path.getsize(f_mbr.name), offset=1048576, whitelist=whitelist)
        dParsed = objVBR.getDictRecord()
    assert dParsed == dExpected


def test_vbr_empty_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'mbr_empty.bin')

    with pytest.raises(InvalidVBRError) as e:
        with open(sampleName, 'rb') as f_vbr:
            objMBR = VolumeBootRecord(f_vbr, os.path.getsize(f_vbr.name), offset=1048576, whitelist=whitelist)
    assert 'Invalid VBR structure: ' in str(e.value)


def test_vbr_gapz_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'vbr_gapz_off_1048576.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'VBR',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': 'NTFS    ',
        'code_SHA256': '96d38c1be37b9124fb71d1d0f5c52969f0074687fe17aef0e1bafc54428674f6'.decode('hex'),
        'record_raw': 'eb52904e5446532020202000020800000000000000f800003f00ff00eefc7f0c0000000080008000ff1f030000000000'
                      '55210000000000000200000000000000f600000001000000b83d71846071849c00000000fa33c08ed0bc007cfb68c007'
                      '1f1e686600cb88160e0066813e03004e5446537515b441bbaa55cd13720c81fb55aa7506f7c101007503e9dd001e83ec'
                      '18681a00b4488a160e008bf4161fcd139f83c4189e581f72e13b060b0075dba30f00c12e0f00041e5a33dbb900202bc8'
                      '66ff06110003160f008ec2ff061600e84b002bc877efb800bbcd1a6623c0752d6681fb54435041752481f90201721e16'
                      '6807bb1668700e1668090066536653665516161668b80166610e07cd1a33c0bf2810b9d80ffcf3aae95f01909066601e'
                      '0666a111006603061c001e66680000000066500653680100681000b4428a160e00161f8bf4cd1366595b5a665966591f'
                      '0f82160066ff06110003160f008ec2ff0e160075bc071f6661c3a0f801e80900a0fb01e80300f4ebfdb4018bf0ac3c00'
                      '7409b40ebb0700cd10ebf2c30d0a41206469736b2072656164206572726f72206f63637572726564000d0a424f4f544d'
                      '4752206973206d697373696e67000d0a424f4f544d475220697320636f6d70726573736564000d0a5072657373204374'
                      '726c2b416c742b44656c20746f20726573746172740d0a008ca9bed6000055aa'.decode('hex'),
        'suspicious_behaviour': ['Suspicious HiddenSectors value: 209714414 (107373779968 bytes)'],
        'known_code_signature': ['NT6.1 VBR'],
    }
    with open(sampleName, 'rb') as f_mbr:
        objVBR = VolumeBootRecord(f_mbr, os.path.getsize(f_mbr.name), offset=32256, whitelist=whitelist)
        dParsed = objVBR.getDictRecord()
    assert dParsed == dExpected

