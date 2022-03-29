#! /usr/bin/env python3

"""
ONTAP REST API Scripts

Purpose: Script to create Volume using ONTAP REST API.

usage:python3 vol_create.py -c cluster1 -vs svm1_cluster1 -aggr -volname -volsize* -fgrp* [grpname] -proto* [nfs/cifs/multi] -sm* [y/n] -sv* [y/n] [-u API_USER] [-p API_PASS]

"""

import base64
import argparse
import logging
from getpass import getpass
import requests
import sys
import urllib3 as ur
import time
ur.disable_warnings()



def get_size(volume_size):
    """Convert MBs to Bytes"""
    tmp = int(volume_size) * 1024 * 1024
    return tmp


def check_job_status(job_status: str, headers_inc: str):
    """ Check job status"""
    #a = job_status['state']
    #type(job_status)
    #
    #print("inside fun", job_status) 
    if job_status['state'] == "failure":
        print("Volume creation failed due to :{}".format(job_status['message']))
    elif job_status['state'] == "success":
        print("Volume "+vol_name+" of "+vol_size+" MB created successfully. Junction path is "+path+" .")
    else:
        job_status_url = "https://{}/api/cluster/jobs/{}".format(clus_name, job_status['uuid'])
        job_response = requests.get(job_status_url, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status( job_status, headers_inc)

   
def crt_vol(unix_perm, SecStyle: str, headers_inc: str):
    """Module to create a volume"""
    #clus_name = ARGS.cluster
    #svmname = ARGS.svm_name
    #aggrname = ARGS.aggr
    #shrproto = ARGS.proto
    #funcgrp = ARGS.fgrp
    #vol_size = ARGS.volsize
    #smirror = ARGS.sm
    #svault = ARGS.sv
    
    volume_size = get_size(vol_size)
        
    vol_url = "https://{}/api/storage/volumes/?return_timeout=30".format(clus_name)
    vol_data = {
        "aggregates.name": [aggrname],
        "svm.name": svmname,
        "name": vol_name,
        "size": volume_size,
        "comment": task_id,
        #"nas": {
        #    "export_policy": {
        #        "name": exp_name
        #    }
        #    
        "nas": {
            "export_policy": {
                "name": exp_name
            },
            
            "path": path,
            "security_style": SecStyle,
            "unix_permissions": unix_perm
            },   
        "snapshot_policy": {
            "name": "default"
            },
            
        "space": {
            "snapshot": {
                "reserve_percent": 10
            }
           }
        }
    

    response = requests.post(vol_url,headers=headers_inc,json=vol_data,verify=False)
    time.sleep(20)
    vol_url = response.json()
    try:
        job_status = "https://{}/{}".format(clus_name,vol_url['job']['_links']['self']['href'])
        job_response = requests.get(job_status, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status(job_status, headers_inc)
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(err)
        sys.exit(1)
    url_text = response.json()
    if 'error' in url_text:
        print(url_text)
        sys.exit(1)
    job_status = "https://{}{}".format(clus_name,url_text['job']['_links']['self']['href'])
    try:
        job_response = requests.get(
            job_status, headers=headers_inc, verify=False)
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(err)
        sys.exit(1)
    url_text = job_response.json()
    if 'error' in url_text:
        print(url_text)
        sys.exit(1)
    job_status = job_response.json()
    print("job_status", job_status)
    check_job_status(job_status, headers_inc )
        
      
        
def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""

    parser = argparse.ArgumentParser(
        description="This script will create an ONTAP volume in an SVM",
    )
    parser.add_argument(
        "-c", "--cluster", required=True, help="API server IP:port details"
    )
    parser.add_argument(
        "-fgrp", required=True, help="Name of the functinal group in caps.")
    parser.add_argument(
        "-vs", "--svm_name", required=True, help="svm name"
    )
    parser.add_argument(
        "-aggr",  required=True, help="Aggregate Name"
    )
    parser.add_argument(
        "-volsize",  required=True, help="Volume Size"
    )
    parser.add_argument(
        "-proto", required=True, help="valid protocal nfs, cifs or multi"
    )
    parser.add_argument(
        "-sm", required=True, help="Is this Volume need Snapmirror? (y/n)"
    )
    parser.add_argument(
        "-sv", required=True, help="Is this Volume need SnapVault? (y/n)"
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


def crt_exp(exp_name: str, headers_inc: str):
    """ Create export policy name and rule """
    
    if shrproto == "nfs":
        
        protocol = "nfs3"
        #ro = rw = su = "sys"
        anon = "65534"
        print()
        clientlist = input("List of Client Match Hostnames, IP Addresses, Netgroups, or Domains:")
        #for loop or while to add more clients to list
        
        exp_data = {
            "name": exp_name,
            "rules": [
                {
                #"allow_device_creation": "true",
                #"allow_suid": "true",
                "anonymous_user": anon,
                
                "clients": [
                    {
                    "match": clientlist
                    }
                ],
                
                "protocols": ["nfs3"],
                "ro_rule": ["sys"],
                "rw_rule": ["sys"],
                "superuser": ["sys"]
                }
            ],
            "svm": {
                "name": svmname,
                "uuid": svm_uuid
            }}
            
        #print(" exp_data json", exp_data) 
        
        exp_url = "https://{}/api/protocols/nfs/export-policies".format(clus_name)
        try:
            response = requests.post(exp_url, headers=headers_inc, json=exp_data, verify=False)
            exp_res = response.json()
            
        except requests.exceptions.HTTPError as err:
            print("inside except") 
            print(err)
            sys.exit(1)
        
        
    elif shrproto == "cifs":
        print()
    
    elif shrproto == "multi":
        print()
    else:
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
    aggrname = ARGS.aggr
    shrproto = ARGS.proto
    funcgrp = ARGS.fgrp
    vol_size = ARGS.volsize
    smirror = ARGS.sm
    svault = ARGS.sv
    
    print()
    #task_id = input("Enter a valid and approved Task number:")
    
    svm_tag = svmname[-4:]
    #svm_tag = svmname.split("-")
    #svm_tag = svm_tag[2]
    
    vol_name = "v_"+svm_tag+"_"+shrproto+"_"+funcgrp.upper()
    path = "/"+vol_name
    Ext_Vol_Style = "flexvol"
    #Space Reserved for Snapshot Copies
    SRSC = 10
    
    svm_url = "https://{}/api/svm/svms?name={}&fields=uuid,language".format(clus_name,svmname)
    try:
        response = requests.get(svm_url, headers=headers, verify=False)
        svm_res = response.json()
        svm_dt = dict(svm_res)
        svm_rd = svm_dt['records']
        
        for i in svm_rd:
            svm = dict(i)
            
        svm_uuid = svm['uuid']
        svm_lang = svm['language']
        
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    
    if ARGS.proto == "nfs":
        
        exp_name = vol_name+"_ip"
        crt_exp(exp_name, headers)
        
        SecStyle = "unix"
        unix_perm = "0755"
        crt_vol(unix_perm, SecStyle, headers)
         #Language: en_US.UTF-8  #if volume is dp, make sure language is same of source svm value.
    elif ARGS.proto == "cifs":
        #Export Policy: cifs-default or default
        cifs_exp_url = "https://{}/api/protocols/nfs/export-policies?name=*default*&rules.protocols=cifs".format(clus_name)
        try:
            response = requests.get(cifs_exp_url, headers=headers, verify=False)
            cifs_exp_res = response.json()
            #print(cifs_exp_res)
            cifs_exp_dt = dict(cifs_exp_res)
            cifs_exp_rd = cifs_exp_dt['records']
            #print(cifs_exp_rd)
            #
            exp_name = chk = []
            for i in cifs_exp_rd:
                cifs_exp = dict(i)
                name = cifs_exp['name']
                exp_name.append(name) 
            #svm_lang = svm['language']
            print(exp_name)
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        if exp_name == chk:
            print("No export policy created for cifs protocol with name tag of 'default'")
            crt = input("Would you like to create default export policy with cifs protocol rule?(y/n):")
            if crt == 'y':
                exp_name = "default"
                
                
        #crt_exp(exp_name, headers)
        
        #SecStyle = "ntfs"
        #unix_perm = "0000"
        #crt_vol(unix_perm, SecStyle, headers)
        print()
        #crt_vol()
        #Junction Path: path
        #Extended Volume Style: flexvol
        #Security Style: ntfs
        #UNIX Permissions: ------------
        #Security Style: ntfs
        #Comment: task_id
        #Space Reserved for Snapshot Copies: 10%
        #Language: en_US.UTF-8  #if volume is dp, make sure language is same of source svm value.
        
        #cifs share create -share-name "EyeC Reports" -path /v_cf03_cifs_OIS0004 -comment "GK:bvandore & sfietta"
    elif ARGS.proto == "multi":
        print()
        #crt_exp()
        #crt_exp_rul()
        #cifs     0.0.0.0/0, ro-any,rw-any,su-any
        #nfs3     ip,ro-sys,rw-sys,su-sys 
        #crt_vol()
        #Volume Size: volsize
        #Junction Path: path
        #Extended Volume Style: flexvol
        #UNIX Permissions: ---rwxr-xr-x
        #Security Style: unix
        #Comment: task_id
        #Space Reserved for Snapshot Copies: 10%
        #Language: en_US.UTF-8  #if volume is dp, make sure language is same of source svm value.
    else:
        print("Invalid protocal, should be nfs, cifs or multi")
        sys.exit()
        
  
    #make_volume(ARGS.cluster,ARGS.volume_name,ARGS.svm_name,ARGS.aggr_name,ARGS.volume_size,headers)