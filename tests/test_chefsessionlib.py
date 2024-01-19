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

__author__ = '''Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>'''
__docformat__ = '''google'''
__date__ = '''18-01-2024'''
__copyright__ = '''Copyright 2024, Costas Tyfoxylos'''
__credits__ = ["Costas Tyfoxylos"]
__license__ = '''Apache Software License 2.0'''
__maintainer__ = '''Costas Tyfoxylos'''
__email__ = '''<ctyfoxylos@schubergphilis.com>'''
__status__ = '''Development'''  # "Prototype", "Development", "Production".

import base64
import datetime
import hashlib
import unittest

from requests import PreparedRequest
from rsa import PrivateKey

from chefsessionlib import ChefSession, InvalidPrivateKey, InvalidAuthenticationVersion
from chefsessionlib.chefsessionlib import ENCODING
from .fixtures.configuration import username, private_key, invalid_private_key, garbage_private_key


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

    def test_current_datetime(self):
        datetime_format = '%Y-%m-%dT%H:%M:%SZ'
        now = datetime.datetime.utcnow().strftime(datetime_format)
        session = ChefSession(username, private_key)
        self.assertEquals(session.get_current_timestamp(), now)

    def test_canonical_path_valid(self):
        path = '/test/one/two'
        self.assertEquals(ChefSession.canonical_path(path), path)

    def test_canonical_path_double_slashes(self):
        path = '//test///one/two//'
        expected = '/test/one/two'
        self.assertEquals(ChefSession.canonical_path(path), expected)

    def test_canonical_path_trailing_slash(self):
        path = '/test/one/two/'
        expected = '/test/one/two'
        self.assertEquals(ChefSession.canonical_path(path), expected)

    def test_canonical_path_single_char(self):
        path = '///'
        expected = '/'
        self.assertEquals(ChefSession.canonical_path(path), expected)

    def test_sign_header_v1_3(self):
        expected = 'version=1.3'
        session = ChefSession(username, private_key, authentication_version='1.3')
        self.assertEquals(session._sign_header(), expected)

    def test_sign_header_v1_0_and_1_1(self):
        valid_versions = ['1.0', '1.1']
        for version in valid_versions:
            expected = f'algorithm=sha1;version={version}'
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session._sign_header(), expected)

    def test_chef_get_request_root_v1_0(self):
        timestamp = '2024-01-19T14:06:47Z'
        method = 'GET'
        path = '/'
        session = ChefSession(username, private_key, authentication_version='1.0')
        hashed_body = session._digest_and_encode('')
        expected = (b'Method:GET\n'
                    b'Hashed Path:QgmbSvAh5T/Y/U4FbCVo18Lj/6g=\n'
                    b'X-Ops-Content-Hash:2jmj7l5rSw0yVb/vlWAYkK/YBwk=\n'
                    b'X-Ops-Timestamp:2024-01-19T14:06:47Z\n'
                    b'X-Ops-UserId:dummy_user')
        self.assertEquals(session._get_chef_request(method, path, hashed_body, timestamp), expected)

    def test_chef_get_request_root_v1_1(self):
        timestamp = '2024-01-19T14:06:47Z'
        method = 'GET'
        path = '/'
        session = ChefSession(username, private_key, authentication_version='1.1')
        hashed_body = session._digest_and_encode('')
        expected = (b'Method:GET\n'
                    b'Hashed Path:QgmbSvAh5T/Y/U4FbCVo18Lj/6g=\n'
                    b'X-Ops-Content-Hash:2jmj7l5rSw0yVb/vlWAYkK/YBwk=\n'
                    b'X-Ops-Timestamp:2024-01-19T14:06:47Z\n'
                    b'X-Ops-UserId:Uln0mSlwHde1AwllEONwGpkhY8s=')
        self.assertEquals(session._get_chef_request(method, path, hashed_body, timestamp), expected)

    def test_chef_get_request_root_v1_3(self):
        timestamp = '2024-01-19T14:06:47Z'
        method = 'GET'
        path = '/'
        session = ChefSession(username, private_key, authentication_version='1.3')
        hashed_body = session._digest_and_encode('')
        expected = (b'Method:GET\n'
                    b'Path:/\n'
                    b'X-Ops-Content-Hash:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=\n'
                    b'X-Ops-Sign:version=1.3\n'
                    b'X-Ops-Timestamp:2024-01-19T14:06:47Z\n'
                    b'X-Ops-UserId:dummy_user\n'
                    b'X-Ops-Server-API-Version:1')
        self.assertEquals(session._get_chef_request(method, path, hashed_body, timestamp), expected)

    def test_sign_v1_0_and_1_1(self):
        # signing b'thisisatest'
        expected = (b'L6\xa3\xcbke\x7f\x04\xa0\x10\xc0Q\x8e{tw\xde\x96\xbbG\xa1\xd5{Q~M \x15/\n\xf5\xb7H~B\xa56\xf5\xcc'
                    b'\xcfi\xce\x1d\xc7\xa2\x0bH\xf2\xed\xb2<T)\xf58\x8e\xef\x06\xac\x98\xe9\xba\xdc\xf8\xb0\xb6vi\x9e'
                    b'\x00\xbe\xf9i8\x1eC\x95:\xfd\x82\n\xcd\'\xa8"\xa0\xde\x064\xc7n\xd5q\x9c\xfa\xd2Z\x03\xf8_K\xaerC'
                    b'\'\xfd|U\xbd%\x9a\xea\xb7+\xd3\xfaH\xf5\x0c\x19\xceW\x9f\x0f\xb3\x06\xf9\x1f\xf0\xb1\xfbYs'
                    b'\x19c2k43Kl\xf4\xc6\xcek5\x90\xbb6\x85T h}\x16\x1c\xac\xb7"\xaa<\xca\x88A"\x02m\xa3\x82\xe1"'
                    b'\xf5VAq\x7fh\xdf6/x1\xf4q\xbe\xac\x0e\xae\x0f\xdao\xc7\xc8)\x8d7D\xf3\x89\xf4\r`\x15\xb3$\xebo'
                    b'\xaa\\\xc6\xacC!\x11\'\xb9\xc2v.\xb4\x11\xca\xbe\xb9w\x84\xc5fD\xeawa\xb8\x8d\xae\xa06V.\x7fJ'
                    b'\xd5h\xc3F\xd4\x0f\xcc\xeeq\x9b\xfb)\xa0t\xb9')
        valid_versions = ['1.0', '1.1']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session._sign(b'thisisatest'), expected)

    def test_sign_v1_3(self):
        # signing b'thisisatest'
        expected = (b'H\x84Z\xa1\x98,\x90t\x9c\xba\xecH\xdfn\xb4bFil\':\xa1\xcb\x89\xa65N\x04w\xf2\xd3\xc9\x1f\xff'
                    b'\xa4Rv\xa4[\x07Y\x1aW\xb1\xca\xe4\x16\x07|6vL8\r\x8d\xde\xc2\xad\xdc@\xcc\x95Ub\xf3\xe0.?'
                    b'\x9a\x0f\xbcb\xb0\x91\x80\xd6\xda\xed\xcf6\x98fY\xdc\r&kO\xe1\xfeW+\xa6\xf6L\x18\x80\xdeO='
                    b'\x0b\xf7Z\x8e\x16\xe4\xac\x07\x90\xf2\xe7tZ=X\xdfAVb"\xfc\xe8j\xa0s\x00\xe0k\x04\xfc\x97'
                    b'\xaaa\x11\x011\xc1\xaf%\x81\xfdB[\xb6\x16\x9b\x184\xfa\xa9\xd5\xc0\xc7>Qp\x11\x1e/\'\xc0k\xbeQ'
                    b'\xabqL\xf9\xe9H\xa9\xaa\xd4\'g\xbcu\x16\xa6\xd7\xa3\xb3\xadv\xd3\x95\xed\x91\x0f\x13\xbe`\xe2'
                    b'\xb3\xfa\x14d\xe9\xa3;\xa3\x0f\xdeGl\x17E\xbe8\x06\xf9\xab\xb4\xdaq\xea\x9eK\xc7\x04\xa4\xe4'
                    b'\xd50k\xf5\xc4\xa07\xf2<\xf3\xc4\x90\xda\x19\xac\xc7.@\xd8\'\r\x054\x8e\x15\xac\xb6\xb3\'\xdb'
                    b'\x90\x0b`\xba')
        session = ChefSession(username, private_key, authentication_version='1.3')
        self.assertEquals(session._sign(b'thisisatest'), expected)

    def test_signed_headers_v1_0_and_1_1(self):
        # signing b'thisisatest'
        expected = {'X-Ops-Authorization-1': 'TDajy2tlfwSgEMBRjnt0d96Wu0eh1XtRfk0gFS8K9bdIfkKlNvXMz2nOHcei',
                    'X-Ops-Authorization-2': 'C0jy7bI8VCn1OI7vBqyY6brc+LC2dmmeAL75aTgeQ5U6/YIKzSeoIqDeBjTH',
                    'X-Ops-Authorization-3': 'btVxnPrSWgP4X0uuckMn/XxVvSWa6rcr0/pI9QwZzlefD7MG+R/wsftZcxlj',
                    'X-Ops-Authorization-4': 'Mms0M0ts9MbOazWQuzaFVCBofRYcrLciqjzKiEEiAm2jguEi9VZBcX9o3zYv',
                    'X-Ops-Authorization-5': 'eDH0cb6sDq4P2m/HyCmNN0TzifQNYBWzJOtvqlzGrEMhESe5wnYutBHKvrl3',
                    'X-Ops-Authorization-6': 'hMVmROp3YbiNrqA2Vi5/StVow0bUD8zucZv7KaB0uQ=='}
        valid_versions = ['1.0', '1.1']
        for version in valid_versions:
            session = ChefSession(username, private_key, authentication_version=version)
            self.assertEquals(session._get_signed_headers(b'thisisatest'), expected)

    def test_signed_headers_v1_3(self):
        # signing b'thisisatest'
        expected = {'X-Ops-Authorization-1': 'SIRaoZgskHScuuxI3260YkZpbCc6ocuJpjVOBHfy08kf/6RSdqRbB1kaV7HK',
                    'X-Ops-Authorization-2': '5BYHfDZ2TDgNjd7CrdxAzJVVYvPgLj+aD7xisJGA1trtzzaYZlncDSZrT+H+',
                    'X-Ops-Authorization-3': 'Vyum9kwYgN5PPQv3Wo4W5KwHkPLndFo9WN9BVmIi/OhqoHMA4GsE/JeqYREB',
                    'X-Ops-Authorization-4': 'McGvJYH9Qlu2FpsYNPqp1cDHPlFwER4vJ8BrvlGrcUz56UipqtQnZ7x1FqbX',
                    'X-Ops-Authorization-5': 'o7OtdtOV7ZEPE75g4rP6FGTpozujD95HbBdFvjgG+au02nHqnkvHBKTk1TBr',
                    'X-Ops-Authorization-6': '9cSgN/I888SQ2hmsxy5A2CcNBTSOFay2syfbkAtgug=='}
        session = ChefSession(username, private_key, authentication_version='1.3')
        self.assertEquals(session._get_signed_headers(b'thisisatest'), expected)

    def test_authenticate_request_v1_0(self):
        timestamp = '2024-01-19T14:06:47Z'
        expected = {'X-Ops-Server-API-Version': 1, 'X-Ops-Sign': 'algorithm=sha1;version=1.0',
                    'X-Ops-UserId': 'dummy_user', 'X-Ops-Timestamp': '2024-01-19T14:06:47Z',
                    'X-Ops-Content-Hash': '2jmj7l5rSw0yVb/vlWAYkK/YBwk=',
                    'X-Ops-Authorization-1': 'maVlM9VtRAljskFRHDZOgeMpIcK5HjCgMTVSnS1JPenOxy/0BfUHWrc0lli5',
                    'X-Ops-Authorization-2': 'hLX6LIwzLIGpvJ8cIN3zc0ckyQWfIS0Y89ssq257luOpJ7l71JGxZ+rJ9HDg',
                    'X-Ops-Authorization-3': '7z3Ct/Iy5bPYifbOrt2opRk4q6Uvu1kEFe5X7n5+6auZ9Jw+A7KERPhtaTDX',
                    'X-Ops-Authorization-4': 'OfdVekE0CtbYKP2rCeFORLRQHXgpW8uAkecyL40hfJxdRyaKq8aJ1qOfgF/X',
                    'X-Ops-Authorization-5': 'VdmEBEwNK7gBzQpe0YPFdNbXHp0/2n90WKXZ4Nvp4BgYDJekxI77X+jzmf54',
                    'X-Ops-Authorization-6': '3Sxk+G9tuo68pm1MOE1zQXgP1504qqbxrsPdGmGZvA=='}
        session = ChefSession(username, private_key, authentication_version='1.0')
        request = PreparedRequest()
        request.headers = {}
        signed_request = session._authenticate_request(request, timestamp)
        self.assertEquals(signed_request.headers, expected)

    def test_authenticate_request_v1_1(self):
        timestamp = '2024-01-19T14:06:47Z'
        expected = {'X-Ops-Server-API-Version': 1, 'X-Ops-Sign': 'algorithm=sha1;version=1.1',
                    'X-Ops-UserId': 'dummy_user', 'X-Ops-Timestamp': '2024-01-19T14:06:47Z',
                    'X-Ops-Content-Hash': '2jmj7l5rSw0yVb/vlWAYkK/YBwk=',
                    'X-Ops-Authorization-1': 'f4Ov5pQBVvdsvwthvXCMo5/ol2eletDt/zXqsGCpUDklRtjlNmqCjmBd08t3',
                    'X-Ops-Authorization-2': 'qw86XcjT4VO2Kfb3rrXhiTNu6UwSlvZLuS5MrtSvHiUPNYGlieaIz+VE57iE',
                    'X-Ops-Authorization-3': '4MHT2t1EiPz0VbYYs2p/G7vl5yLq7Se6+0Ak41oTwRpOR+ukJ4NTvh39L4wF',
                    'X-Ops-Authorization-4': 'wKsMY5HgSeNKmqC9rgpmSWJVX6q6EmJdSG11R39zVl2OlYZ750FpmNKeDxZr',
                    'X-Ops-Authorization-5': '3zSHxKIZHAItLYtoY9icZ//BZwFW6JTOovTSkqCa/aL0LFatQPYPqSf5Zr7A',
                    'X-Ops-Authorization-6': 'Sz6zm6VPW10KtxTPnh2ruIfwTk8oJR/oStfexB345w=='}
        session = ChefSession(username, private_key, authentication_version='1.1')
        request = PreparedRequest()
        request.headers = {}
        signed_request = session._authenticate_request(request, timestamp)
        self.assertEquals(signed_request.headers, expected)

    def test_authenticate_request_v1_3(self):
        timestamp = '2024-01-19T14:06:47Z'
        expected = {'X-Ops-Server-API-Version': 1, 'X-Ops-Sign': 'version=1.3', 'X-Ops-UserId': 'dummy_user',
                    'X-Ops-Timestamp': '2024-01-19T14:06:47Z',
                    'X-Ops-Content-Hash': '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=',
                    'X-Ops-Authorization-1': 'F5AYVkvhpOvZLj2B8CM4bMRiD5S2kbd2xGxtmJIuFVCfEBSU9tYZ3i8ol1ZC',
                    'X-Ops-Authorization-2': 'Hv5snixffPsZJ1NPvoXGXu8/JBL4nl958lKObsHdZkNDxZujBM4jPhhI143l',
                    'X-Ops-Authorization-3': '4QtV1RKo3t5RoTZ2CjZmx3pOMfP/kvn9K723pmCqCfBfAkFOz53t3xfa4Wvw',
                    'X-Ops-Authorization-4': '2vetv7dFXkf4yEQFUkTIdZqeSgTnacWyEIavOc5rdKwNFrgtzA3ERRe3Rvns',
                    'X-Ops-Authorization-5': 'gl8srzAp003lrG34ONrP6tFIJXXXzBfb0CasS2RmrwSNyegBaPOiZ0y9pcIK',
                    'X-Ops-Authorization-6': 'zebUCrU7q/ay8ikQWPyOJ5w81gizo+NU1li+7aDp8Q=='}
        session = ChefSession(username, private_key, authentication_version='1.3')
        request = PreparedRequest()
        request.headers = {}
        signed_request = session._authenticate_request(request, timestamp)
        self.assertEquals(signed_request.headers, expected)

    def tearDown(self):
        """
        Test tear down

        This is where you should tear down what you've setup in setUp before. This method is called after every test.
        """
        pass
