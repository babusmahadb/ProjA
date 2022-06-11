
import base64
import argparse
import logging
from getpass import getpass
import requests
import sys
import urllib3 as ur
import time
import re
import json
ur.disable_warnings()

def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""

    parser = argparse.ArgumentParser(
        description="This script will create an ONTAP volume in an SVM",
    )
    parser.add_argument(
        "-c", "--cluster", required=True, help="API server IP:port details"
    )
    parser.add_argument(
        "-fgrp", required=False, help="Name of the functinal group in caps.")
    parser.add_argument(
        "-vs", "--svm_name", required=True, help="svm name"
    )
    parser.add_argument(
        "-aggr",  required=False, help="Aggregate Name"
    )
    parser.add_argument(
        "-volname",  required=True, help="Volume Size"
    )
    parser.add_argument(
        "-volsize",  required=False, help="Volume Size"
    )
    parser.add_argument(
        "-proto", required=False, help="valid protocal nfs, cifs or multi"
    )
    parser.add_argument(
        "-sm", required=False, help="Is this Volume need Snapmirror? (y/n)"
    )
    parser.add_argument(
        "-sv", required=False, help="Is this Volume need SnapVault? (y/n)"
    )
    parser.add_argument(
        "-u",
        "--api_user",
        default="admin",
        help="API Username")
    parser.add_argument("-p", "--api_pass", help="API Password")
    parsed_args = parser.parse_args()

    # collect the password without echo if not already provided
    if not parsed_args.api_pass:
        parsed_args.api_pass = getpass()

    return parsed_args

def mnt_vol(vol_name: str, headers: str):

    mnt_obj = {
        "nas": {
            "path": path
            }
        }

    mnt_url = "https://{}/api/storage/volumes?name={}".format(clus_name,vol_name)
    response = requests.patch(mnt_url, headers=headers, json=mnt_obj, verify=False)
    mnt_json = response.json()
    
    #{'uuid': '18b54986-e945-11ec-9591-005056b09de7', '_links': {'self': {'href': '/api/cluster/jobs/18b54986-e945-11ec-9591-005056b09de7'}}}
    m = dict(mnt_json)
    n = m['jobs']
    for t in n:
        u = t['uuid']
    
    href = "api/cluster/jobs/"+u+""    
    
    mnt_chk = "https://{}/{}".format(clus_name,href)
    response = requests.get(mnt_chk, headers=headers, verify=False)
    mnt_chk = response.json()
    
    mnt_state = mnt_chk['state']
    if mnt_state == "success":
        print("Volume "+vol_name+" mounted successfully.")
    else:
        print("Volume mount failed", mnt_chk)
    print()
    
	
	
	
if __name__ == "__main__":
    
    
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
    )
    ARGS = parse_args()
    BASE64STRING = base64.encodebytes(
        ('%s:%s' %
         (ARGS.api_user, ARGS.api_pass)).encode()).decode().replace('\n', '')

    headers = {
        'authorization': "Basic %s" % BASE64STRING,
        'content-type': "application/json",
        'accept': "application/json"
    }
    
    clus_name = ARGS.cluster
    svmname = ARGS.svm_name
    #aggrname = ARGS.aggr
    vol_name = ARGS.volname
    path = "/"+vol_name
    
    mnt_vol(vol_name, headers)