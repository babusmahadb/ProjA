#! /usr/bin/env python3

"""
ONTAP REST API Sample Scripts

This script was developed by NetApp to help demonstrate NetApp
technologies.  This script is not officially supported as a
standard NetApp product.

Purpose: Script to create Volume using ONTAP REST API.

usage:python3 create_volume.py [-h] -c CLUSTER -v VOLUME_NAME -vs SVM_NAME -a
                        AGGR_NAME -sz VOLUME_SIZE [-u API_USER] [-p API_PASS]

Copyright (c) 2020 NetApp, Inc. All Rights Reserved.
Licensed under the BSD 3-Clause “New” or Revised” License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
https://opensource.org/licenses/BSD-3-Clause

"""

import base64
import argparse
import logging
from getpass import getpass
import requests
import sys
import urllib3 as ur
ur.disable_warnings()