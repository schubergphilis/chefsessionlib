#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: test_chefsessionlib.py
#
# Copyright 2024 Costas Tyfoxylos, Daan de Goede
#
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#

"""
test_chefsessionlib
----------------------------------
Tests for `chefsessionlib` module.

.. _Google Python Style Guide:
   http://google.github.io/styleguide/pyguide.html

"""

import unittest

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-01-2024'''
__copyright__ = '''Copyright 2024, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

from .fixtures.configuration import username, private_key, invalid_private_key, garbage_private_key
from chefsessionlib import ChefSession, InvalidPrivateKey, InvalidAuthenticationVersion
from chefsessionlib.chefsessionlib import ENCODING
from rsa import PrivateKey
import base64
import hashlib
from requests import Session


class TestChefsessionlib(unittest.TestCase):

    def setUp(self):
        """
        Test set up

        This is where you can setup things that you use throughout the tests. This method is called before every test.
        """
        pass

    def test_valid_private_key(self):
        key = ChefSession._validate_private_key(private_key)
        self.assertIsInstance(key, PrivateKey)

    def test_invalid_private_key(self):
        with self.assertRaises(InvalidPrivateKey):
            ChefSession._validate_private_key(invalid_private_key)

    def test_garbage_private_key(self):
        with self.assertRaises(InvalidPrivateKey):
            ChefSession._validate_private_key(garbage_private_key)

    def test_valid_authentication_versions(self):
        valid_versions = ['1.0', '1.1', '1.3']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session.authentication_version, version)

    def test_invalid_authentication_versions(self):
        for invalid_versions in ['a', 1.0, '1', '1.2']:
            with self.assertRaises(InvalidAuthenticationVersion):
                ChefSession(username, private_key, authentication_version=invalid_versions)

    def test_user_id(self):
        session = ChefSession(username, private_key)
        self.assertEquals(session.user_id, username)

    def test_canonical_user_id_v1_0_and_1_3(self):
        valid_versions = ['1.0', '1.3']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session.canonical_user_id, username)

    def test_canonical_user_id_v1_1(self):
        expected = base64.b64encode(hashlib.sha1(username.encode(ENCODING)).digest()).decode(ENCODING)
        session = ChefSession(username, private_key, authentication_version='1.1')
        self.assertEquals(session.canonical_user_id, expected)

    def test_hashing_method_name_v1_3(self):
        session = ChefSession(username, private_key, authentication_version='1.3')
        self.assertEquals(session.hashing_method, 'sha256')

    def test_hashing_method_name_v1_0_and_1_1(self):
        valid_versions = ['1.0', '1.1']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session.hashing_method, 'sha1')

    def test_hashing_method_v1_3(self):
        session = ChefSession(username, private_key, authentication_version='1.3')
        self.assertEquals(session._hashing_method, hashlib.sha256)

    def test_hashing_method_v1_0_and_1_1(self):
        valid_versions = ['1.0', '1.1']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session._hashing_method, hashlib.sha1)

    def test_digest_and_encode_v1_0_and_1_1_short(self):
        expected = 'qUqP5cyxm6YcTAhz05Hph5gvu9M='  # 'test' string
        valid_versions = ['1.0', '1.1']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session._digest_and_encode('test'), expected)

    def test_digest_and_encode_v1_0_and_1_1_long(self):
        expected = 'Cz8zvMdFQJ49Q9MW/mS0JlRU5uA='  # 'test'*20 string
        valid_versions = ['1.0', '1.1']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session._digest_and_encode('test' * 20), expected)

    def test_digest_and_encode_v1_3_short(self):
        expected = 'n4bQgYhMfWWaL+qgxVrQFaO/TxsrC4Is0V1sFbDwCgg='  # 'test' string
        session = ChefSession(username, private_key, authentication_version='1.3')
        self.assertEquals(session._digest_and_encode('test'), expected)

    def test_digest_and_encode_v1_3_long(self):
        expected = 'ttaMFb2y4hfVMQMU3MP5chPyaGuOh0+g0a6gKKg7QNw='  # 'test'*20 string
        session = ChefSession(username, private_key, authentication_version='1.3')
        self.assertEquals(session._digest_and_encode('test' * 20), expected)

    def tearDown(self):
        """
        Test tear down

        This is where you should tear down what you've setup in setUp before. This method is called after every test.
        """
        pass
