#!/usr/bin/env python
# -*- coding: utf-8 -*-
# File: chefsessionlibexceptions.py
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
Custom exception code for chefsessionlib.

.. _Google Python Style Guide:
   https://google.github.io/styleguide/pyguide.html

"""

__author__ = 'Costas Tyfoxylos <ctyfoxylos@schubergphilis.com>, Daan de Goede <ddegoede@schubergphilis.com>'
__docformat__ = 'google'
__date__ = '18-01-2024'
__copyright__ = 'Copyright 2024, Costas Tyfoxylos, Daan de Goede'
__credits__ = ["Costas Tyfoxylos, Daan de Goede"]
__license__ = 'Apache Software License 2.0'
__maintainer__ = 'Costas Tyfoxylos, Daan de Goede'
__email__ = '<ctyfoxylos@schubergphilis.com>, <ddegoede@schubergphilis.com>'
__status__ = 'Development'  # "Prototype", "Development", "Production".


class InvalidAuthentication(Exception):
    """The authentication did not succeed."""


class InvalidPrivateKey(Exception):
    """The content is not a valid str of a rsa private key."""


class InvalidAuthenticationVersion(Exception):
    """The version provided is not supported."""
