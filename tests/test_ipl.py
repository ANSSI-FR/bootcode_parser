#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from bootcode_parser import InitialProgramLoader, InvalidIPLError
import os
import pytest


def test_ipl_nt5_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'ipl_5.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'IPL',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': None,
        'code_SHA256': '525788a688cfbe9e416122f0bc3cfb32ce9699fd12356b6ccaa173444c7d8f3f'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT5.1/NT5.2 IPL'],
    }
    with open(sampleName, 'rb') as f_ipl:
        objIPL = InitialProgramLoader(f_ipl, os.path.getsize(f_ipl.name), whitelist=whitelist)
        dParsed = objIPL.getDictRecord()
        dParsed.pop('record_raw')
    assert dParsed == dExpected


def test_ipl_nt60_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'ipl_60.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'IPL',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': None,
        'code_SHA256': 'ff1aae04bac3e29f062a7fa17320d7d26363256a69f96840718d45301da71291'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.0 IPL'],
    }
    with open(sampleName, 'rb') as f_ipl:
        objIPL = InitialProgramLoader(f_ipl, os.path.getsize(f_ipl.name), whitelist=whitelist)
        dParsed = objIPL.getDictRecord()
        dParsed.pop('record_raw')
    assert dParsed == dExpected


def test_ipl_nt61_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'ipl_61.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'IPL',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': None,
        'code_SHA256': '462afe2322bad3d1c2747d7437d5f6c157e00ca37e5d38ebedd25346b3b488ce'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.1 IPL'],
    }
    with open(sampleName, 'rb') as f_ipl:
        objIPL = InitialProgramLoader(f_ipl, os.path.getsize(f_ipl.name), whitelist=whitelist)
        dParsed = objIPL.getDictRecord()
        dParsed.pop('record_raw')
    assert dParsed == dExpected


def test_ipl_nt62_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'ipl_62.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'IPL',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': None,
        'code_SHA256': 'c09d496a1f24086c333468d58256d5db9c73fee945fca74603bdab05f19a6d57'.decode('hex'),
        'suspicious_behaviour': [],
        'known_code_signature': ['NT6.2+ IPL'],
    }
    with open(sampleName, 'rb') as f_ipl:
        objIPL = InitialProgramLoader(f_ipl, os.path.getsize(f_ipl.name), whitelist=whitelist)
        dParsed = objIPL.getDictRecord()
        dParsed.pop('record_raw')
    assert dParsed == dExpected


def test_ipl_empty_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'ipl_empty.bin')

    with pytest.raises(InvalidIPLError) as e:
        with open(sampleName, 'rb') as f_ipl:
            objIPL = InitialProgramLoader(f_ipl, os.path.getsize(f_ipl.name), whitelist=whitelist)
    assert 'Invalid IPL structure: ' in str(e.value)


def test_ipl_rovnix_with_whitelist(whitelist):
    sampleName = os.path.join('test_data', 'ipl_rovnix.bin')

    dParsed = {}
    dExpected = {
        'record_type': 'IPL',
        'sample_name': sampleName,
        'partition_table': [],
        'disk_signature': None,
        'oem_id': None,
        'code_SHA256': '51605476b580fd6e38b22cc0a2a2aad18102806117c45b70c73f39a6a93b7aed'.decode('hex'),
        'suspicious_behaviour': ['Unknown Interrupt : 0x70'],
        'known_code_signature': [],
    }
    with open(sampleName, 'rb') as f_ipl:
        objIPL = InitialProgramLoader(f_ipl, os.path.getsize(f_ipl.name), whitelist=whitelist)
        dParsed = objIPL.getDictRecord()
        dParsed.pop('record_raw')
    assert dParsed == dExpected

