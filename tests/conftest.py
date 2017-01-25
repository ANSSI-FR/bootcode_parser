#!/usr/bin/env python2
# -*- coding:utf-8 -*-

from __future__ import unicode_literals
import csv
import os
import pytest


BOOTRECORD_WHITELIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'bootrecord_whitelist.csv')


@pytest.fixture(scope='module')
def whitelist(request):
    lWhitelist = []
    # CSV file content should be "Type,SHA256,Comment"
    with open(BOOTRECORD_WHITELIST_PATH, 'rb') as fd:
        reader = csv.DictReader(fd)
        for row in reader:
            lWhitelist.append(row)
    return lWhitelist

