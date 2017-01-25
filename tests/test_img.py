#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
from bootcode_parser import *
import bootcode_parser
import pytest
import pytest_catchlog
import os
import logging


def test_img_nt5_with_whitelist(caplog, whitelist):
    sampleName = os.path.join('test_data', 'disk_5.img')
    caplog.set_level(logging.INFO)
    with open(sampleName, 'rb') as f_img:
        parseImageFile(f_img, sectorSize=512, whitelist=whitelist)
    assert caplog.record_tuples == [
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT5.1/NT5.2 MBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT5.1/NT5.2 VBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT5.1/NT5.2 IPL']")
    ]



def test_img_nt60_with_whitelist(caplog, whitelist):
    sampleName = os.path.join('test_data', 'disk_60.img')
    caplog.set_level(logging.INFO)
    with open(sampleName, 'rb') as f_img:
        parseImageFile(f_img, sectorSize=512, whitelist=whitelist)
    assert caplog.record_tuples == [
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.0 MBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.0 VBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.0 IPL']")
    ]


def test_img_nt61_with_whitelist(caplog, whitelist):
    sampleName = os.path.join('test_data', 'disk_61.img')
    caplog.set_level(logging.INFO)
    with open(sampleName, 'rb') as f_img:
        parseImageFile(f_img, sectorSize=512, whitelist=whitelist)
    assert caplog.record_tuples == [
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.1+ MBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.1 VBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.1 IPL']")
    ]


def test_img_nt62_with_whitelist(caplog, whitelist):
    sampleName = os.path.join('test_data', 'disk_62.img')
    caplog.set_level(logging.INFO)
    with open(sampleName, 'rb') as f_img:
        parseImageFile(f_img, sectorSize=512, whitelist=whitelist)
    assert caplog.record_tuples == [
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.1+ MBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.2+ VBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.2+ IPL']")
    ]


def test_img_gapz_with_whitelist(caplog, whitelist):
    sampleName = os.path.join('test_data', 'disk_gapz.img')
    caplog.set_level(logging.INFO)
    with open(sampleName, 'rb') as f_img:
        parseImageFile(f_img, sectorSize=512, whitelist=whitelist)
    assert caplog.record_tuples == [
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.1+ MBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT6.1 VBR']"),
        (bootcode_parser.__file__, logging.WARNING, "Suspicious behaviours were detected: [u'Suspicious HiddenSectors "
                                                    "value: 209714414 (107373779968 bytes)']"),
        (bootcode_parser.__file__, logging.WARNING, "VBR of the active partition located at sector 2048 (offset "
                                                    "1048576) is suspicious (see previous warning). This could mean "
                                                    "that the partition table in the MBR or the BPB in the VBR has "
                                                    "been tampered with !"),
        (bootcode_parser.__file__, logging.WARNING, "HiddenSectors value in BiosParameterBlock is different than actual"
                                                    " offset in partition table ! HiddenSectors=209714414, partition"
                                                    " table offset=2048"),
        (bootcode_parser.__file__, logging.ERROR, "Invalid IPL structure: expected 2, found 0\n")
    ]


def test_img_rovnix_with_whitelist(caplog, whitelist):
    sampleName = os.path.join('test_data', 'disk_rovnix.img')
    caplog.set_level(logging.INFO)
    with open(sampleName, 'rb') as f_img:
        parseImageFile(f_img, sectorSize=512, whitelist=whitelist)
    assert caplog.record_tuples == [
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT5.1/NT5.2 MBR']"),
        (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['NT5.1/NT5.2 VBR']"),
        (bootcode_parser.__file__, logging.WARNING, "No known code signature were found, this is highly suspicious."),
        (bootcode_parser.__file__, logging.WARNING, "Suspicious behaviours were detected: [u'Unknown Interrupt : 0x70']")
    ]


def test_img_tc_with_whitelist(caplog, whitelist):
    sampleName = os.path.join('test_data', 'disk_tc.img')
    caplog.set_level(logging.INFO)
    with open(sampleName, 'rb') as f_img:
        parseImageFile(f_img, sectorSize=512, whitelist=whitelist)
    assert caplog.record_tuples[0] == (bootcode_parser.__file__, logging.INFO, "Known signatures found: ['TrueCrypt MBR']")
    assert caplog.records[1].levelno == logging.ERROR
    assert caplog.records[1].message.startswith("Invalid VBR structure:")
