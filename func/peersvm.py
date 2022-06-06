
import base64
import argparse
import logging
from getpass import getpass
import requests
import sys
import urllib3 as ur
import time
import re
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
        "-vs", "--svm_name", required=False, help="svm name"
    )
    parser.add_argument(
        "-aggr",  required=False, help="Aggregate Name"
    )
    parser.add_argument(
        "-volname",  required=False, help="Volume Size"
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

def snpchk(clstr: str, headers: str):
        
    print()
    svm_peer = get_svm_peer(clstr, headers)
    
    print()
    print("Source Cluster/SVM "+str(clstr)+"/"+str(svm_peer)+" .")
    print()
	
def get_svm_peer(cluster: str, headers_inc: str):
    """ get cluster peer details """

    svm_pr_url = "https://{}/api/svm/peers?svm.name=*".format(cluster)
    try:
        response = requests.get(svm_pr_url, headers=headers_inc, verify=False)
        #print(response.json())
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(err)
        sys.exit(1)
    
    svm_pr_json = response.json()
    #print(svm_pr_json)
    svm_pr_dt = dict(svm_pr_json)
    
    svm_pr_rd = svm_pr_dt['records']
    
    print(svm_pr_rd)
    
    svm_lst = []
    
    for r in svm_pr_rd:
        b = dict(r)
        p = b['svm']
        #for p in b:
        svm_pr_lt = p['name']
        if svm_pr_lt not in svm_lst:
            svm_lst.append(svm_pr_lt)
        
    print("Peer SVM for "+str(cluster)+" is "+str(svm_lst)+".")
    print()
    
    return svm_lst	
	
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
    #svmname = ARGS.svm_name
    ##aggrname = ARGS.aggr
    #vol_name = ARGS.volname
    #path = "/"+vol_name
    
    snpchk(clus_name, headers)