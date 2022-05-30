
#! /usr/bin/env python3

"""
ONTAP REST API Scripts

Purpose: Script to create Volume using ONTAP REST API.

usage:python3 vol_create.py -c cluster1 -vs svm1_cluster1 -aggr -volname -volsize -fgrp [grpname] -proto [nfs/cifs/multi] -sm [y/n] -sv [y/n] [-u API_USER] [-p API_PASS]

"""


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


def get_size(volume_size: str):
    """Convert GBs/TBs to Bytes"""
    volume_num = volume_size[:-2]
    volume_unit = volume_size[-2:]
    #print("volume_num "+volume_num+" volume_unit: "+volume_unit+".")
    tmp = 0
    if (volume_unit == "mb" or volume_unit == "MB"):
        tmp = float(volume_num) * 1024 * 1024
    elif (volume_unit == "gb" or volume_unit == "GB"):
        tmp = float(volume_num) * 1024 * 1024 * 1024
    elif (volume_unit == "tb" or volume_unit == "TB"):
        tmp = float(volume_num) * 1024 * 1024 * 1024 * 1024
    else:
        print("Volume size is invalid, use ex: 1MB|1GB|1TB ")
        sys.exit()
    return tmp


def check_job_status(job_status: str, headers_inc: str):
    """ Check job status"""
    print()

    if job_status['state'] == "failure":
        print("Volume creation failed due to :{}".format(job_status['message']))
    elif job_status['state'] == "success":
        print("Volume "+vol_name+" of "+vol_size.upper()+" created successfully. Junction path is "+path+" .")
    else:
        job_status_url = "https://{}/api/cluster/jobs/{}".format(clus_name, job_status['uuid'])
        job_response = requests.get(job_status_url, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status( job_status, headers_inc)
   
def crt_vol(volume_size, SecStyle: str, headers_inc: str):
    """Module to create a volume"""
        
    snap_url = "https://{}/api/storage/snapshot-policies?copies.snapmirror_label=daily&name=*default*&copies.prefix=4hourly&copies.count=6".format(clus_name)
    response = requests.get(snap_url, headers = headers, verify=False)
    snap_res = response.json()
    
    snap_dt = dict(snap_res)
    snap_rd = snap_dt['records']
    snap_list=[]
    for i in snap_rd:
        snap = dict(i)
        snap_policy = snap['name']
        snap_copies = snap['copies']
        
        for j in snap_copies:
            pref = j['prefix']
            cnt = j['count']
            if (pref == "daily" and cnt == 7):
                snap_list.append(snap_policy)
    
    if smirror == "y":
        
        typ = "dp"
        lang = svm_lang
        snapshot_policy = "none"
        smirror == "n"
        
    else:
        typ = "rw"
        lang = svm_lang
        print()    
        snapshot_policy = input("Pick the snapshot policy for volume "+vol_name+" ,"+str(snap_list)+": ")    
    
    vol_url = "https://{}/api/storage/volumes/?return_timeout=30".format(clus_name)
    vol_data = {
        "aggregates.name": [aggrname],
        "svm.name": svmname,
        "name": vol_name,
        "type": typ,
        "language": lang,
        "size": volume_size,
        "comment": task_id,
         
        "nas": {
            "export_policy": {
                "name": exp_name
            },
            
            "path": path,
            "security_style": SecStyle,
            
            },   
        "snapshot_policy": {
            "name": snapshot_policy
            },
            
        "space": {
            "snapshot": {
                "reserve_percent": 10
            }
           }
        }
    

    response = requests.post(vol_url,headers=headers_inc,json=vol_data,verify=False)
    time.sleep(20)
    vol_res = response.json()
    try:
        job_status = "https://{}/{}".format(clus_name,vol_res['job']['_links']['self']['href'])
        job_response = requests.get(job_status, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status(job_status, headers_inc)
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(err)
        sys.exit(1)


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
        "-volname",  required=False, help="Volume Size"
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



def get_exp_id(exp_name: str, headers_inc: str):
    """ Get's Export Policy ID using policy name """
    
    exp_id_url = "https://{}/api/protocols/nfs/export-policies/?name={}".format(clus_name,exp_name)
    response = requests.get(exp_id_url, headers=headers_inc, verify=False)
    exp_id_res = response.json()
    
    exp_id_dt = dict(exp_id_res)
    exp_id_rd = exp_id_dt['records']
    
    for i in exp_id_rd:
        pid = dict(i)
        print("pid ",pid)
    
    exp_id = pid['id']
                
    return  exp_id           


def crt_add_rule(rest_client: str, exp_id: str, headers_inc: str):
    """ add's additional rule existing expolicy """
    
    
    for host in rest_client:
            
        rule_add = {
            
                "clients": [
                    {
                    "match": host
                    }
                ],
                
                "protocols": ["nfs3"],
                "ro_rule": ["sys"],
                "rw_rule": ["sys"],
                "superuser": ["sys"]
                }
        
        exp_url = "https://{}/api/protocols/nfs/export-policies/{}/rules".format(clus_name,exp_id)
        try:
            response = requests.post(exp_url, headers=headers_inc, json=rule_add, verify=False)
            exp_res = response.json()
            
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        
        print("Rule for export Policy '"+exp_name+"' updated with protocol nfs3 for volume '"+vol_name+"' having access ro/rw/su of sys for client '"+host+"'.")
                
                
def crt_pol_rule(client: str, headers_inc: str):
    """ creates export policy name and rule index 1 """
    anon = "65534"
    
    exp_data = {
        "name": exp_name,
        "rules": [
            {
            
            "anonymous_user": anon,
            
            "clients": [
                {
                "match": client
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
    
    
    exp_url = "https://{}/api/protocols/nfs/export-policies".format(clus_name)
    try:
        response = requests.post(exp_url, headers=headers_inc, json=exp_data, verify=False)
        exp_res = response.json()
        
    except requests.exceptions.HTTPError as err:
        
        print(err)
        sys.exit(1)
    print()
    print("Export policy '"+exp_name+"' created for volume '"+vol_name+"' with rule ro/rw/su of sys for clients '"+client+"'.")
    print()
    


def crt_cifs_exp(exp_name: str, headers_inc: str):   
    """ cifs export policy rule create """
    
    anon = "65534"
    print()
    
    exp_data = {
        "name": exp_name,
        "rules": [
            {
            
            "anonymous_user": anon,
            
            "clients": [
                {
                "match": "0.0.0.0/0"
                }
            ],
            
            "protocols": ["cifs"],
            "ro_rule": ["any"],
            "rw_rule": ["any"],
            "superuser": ["any"]
            }
        ],
        "svm": {
            "name": svmname,
            "uuid": svm_uuid
        }}
            
    exp_url = "https://{}/api/protocols/nfs/export-policies".format(clus_name)
    try:
        response = requests.post(exp_url, headers=headers_inc, json=exp_data, verify=False)
        exp_res = response.json()
        
    except requests.exceptions.HTTPError as err:
         
        print(err)
        sys.exit(1)
    print("Policy '"+exp_name+"' created with cifs protocol clientmatch of 0.0.0.0/0")
                    

def crt_exp(exp_name: str, headers_inc: str):
    """ Create export policy name and rule """
    
    if shrproto == "nfs":
                
        print()
        clientlist = input("List of Client Match Hostnames, IP Addresses, Netgroups, or Domains: ")
        
        client_num = clientlist.split(",")
        first_client = client_num[0]
        rest_client = client_num[1:]
        
        #sys.exit(1)
        if len(client_num) > 1:
                    
            crt_pol_rule(first_client,headers_inc)
            
            exp_id = get_exp_id(exp_name, headers_inc)
        
            crt_add_rule(rest_client, exp_id, headers_inc)
                    
        else:
            
            crt_pol_rule(clientlist,headers_inc)
               
    elif shrproto == "cifs":
        
        crt_cifs_exp(exp_name, headers_inc) 
            
    elif shrproto == "multi":
        
        exp_name = vol_name+"_ip"
               
        crt_cifs_exp(exp_name, headers_inc)
        
        exp_id = get_exp_id(exp_name, headers_inc)
        
        print()
        clientlist = input("List of Client Match Hostnames, IP Addresses, Netgroups, or Domains: ")
                
        client_num = clientlist.split(",")
        
        if len(client_num) > 1:
            
            crt_add_rule(client_num, exp_id, headers_inc)
            
        else:
            
            rule_add = {
            
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
        
            exp_url = "https://{}/api/protocols/nfs/export-policies/{}/rules".format(clus_name,exp_id)
            try:
                response = requests.post(exp_url, headers=headers_inc, json=rule_add, verify=False)
                exp_res = response.json()
                
            except requests.exceptions.HTTPError as err:
                print(err)
                sys.exit(1)
            
            print("Rule for export Policy '"+exp_name+"' updated with protocol nfs3 for volume '"+vol_name+"' having access ro/rw/su of sys for client '"+clientlist+"'.")
        
    else:
        print()
        print("Existing script")
        sys.exit(1)



def crt_share(svm_uuid: str, headers_inc: str):
    """ create new cifs share for volume """
        
    print()
    share_name = input("Enter cifs share name for "+vol_name+": ")
    print()
    share_comment = input("Enter share comment mentioning share owner details: ")
    
    cifs_share_data = {
    
        "comment": share_comment,
        "name": share_name,
        "path": path,
        "svm": {
            "name": svmname,
            "uuid": svm_uuid
        }            }
        
    cifs_share_url = "https://{}/api/protocols/cifs/shares/".format(clus_name)
    
    #Language: en_US.UTF-8  #if volume is dp, make sure language is same of source svm value.
    
    try:
        response = requests.post(cifs_share_url,headers=headers,json=cifs_share_data,verify=False)
        cifs_share_res = response.json()
        
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    print()
    print("CIFS share '"+share_name+"' create with path "+path+".")
        


def get_svm():
    """ Get SVM nane and UUID """
    
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
        
    return svm_uuid,svm_lang    
 
    
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
    funcgrp = ARGS.fgrp.upper()
    vol_size = ARGS.volsize
    smirror = ARGS.sm
    svault = ARGS.sv
    
    volume_size = get_size(vol_size)   
    
    find_url = "https://{}/api/storage/volumes/?name=*{}*".format(clus_name,funcgrp)
    try:
        response = requests.get(find_url, headers=headers, verify=False)
        find_res = response.json()
        
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    if "error" in find_res:
        print()
        print("Invalid username/password")
        print(find_res)
        sys.exit(1)
        
    find_dt = dict(find_res)
    find_rd = find_dt['records']
    vn_list = []
    for i in find_rd:
        vl = dict(i)
        vln = vl['name']
        vln = vln.split("_")
        vln = vln[3]
        vn_list.append(vln[-4:])
    
    num_list = [n for n in vn_list if n.isdigit()]
    
    if len(num_list) == 0:
        vid = "0000"
    else:    
        vid = max(num_list)
    
    res = re.sub(r'[0-9]+$', lambda x: f"{str(int(x.group())+1).zfill(len(x.group()))}",vid)
    
    
       
    svmd = get_svm()
    svm_uuid = svmd[0]
    svm_lang = svmd[1]
    
    print()    
    task_id = input("Enter a valid and approved Task number:")
    
    
        
    #svm_tag = svmname[-4:]
    svm_tag = svmname.split("-")
    if len(svm_tag) == 0:
        svm_tag = svmname.split("_")
        svm_tag = svm_tag[2]
    else:
        svm_tag = svm_tag[2]
    
    
    if ARGS.volname:
        vol_name = ARGS.volname
    else:
        vol_name = "v_"+svm_tag+"_"+shrproto+"_"+funcgrp.upper()+res
    
    path = "/"+vol_name
    Ext_Vol_Style = "flexvol"
    #Space Reserved for Snapshot Copies
    SRSC = 10
    

    if smirror == "y":
        
        print()
        peer_clus = input("Enter a Target Cluster name/IP for SnapMirror Configuration: ")
        peer_svm = input("Enter a Target SVM Name: ")
        peer_aggr = input("Enter a Target Aggregate Name: ")
        print()
        
        clus_name = peer_clus
        vol_name = vol_name+"_mir"
        exp_name = vol_name
        
        #crt_exp(exp_name, headers)
        
        aggrname = peer_aggr
        svmname = peer_svm
        #snapshot_policy = "default"
        
        crt_exp(exp_name, headers)
        
        if (ARGS.proto == "nfs" or ARGS.proto == "multi"):
            SecStyle = "unix"
        elif ARGS.proto == "cifs":
            SecStyle = "ntfs"
        else:
            print("Invalid protocal, should be nfs, cifs or multi")
            sys.exit()
            
        crt_vol(volume_size, SecStyle, headers)
        
        #crt_estab_snpmir()
        
    if ( ARGS.proto == "nfs" or ARGS.proto == "multi"):
        
        exp_name = vol_name+"_ip"
        
        crt_exp(exp_name, headers)
        
        SecStyle = "unix"
        
        crt_vol(volume_size, SecStyle, headers)
         #Language: en_US.UTF-8  #if volume is dp, make sure language is same of source svm value.
    
    
    elif ARGS.proto == "cifs":
    
        #Export Policy: cifs-default or default
        cifs_exp_name = []
        cifs_exp_url = "https://{}/api/protocols/nfs/export-policies?name=*default*&rules.protocols=cifs&svm.name={}".format(clus_name,svmname)
        try:
            response = requests.get(cifs_exp_url, headers=headers, verify=False)
            cifs_exp_res = response.json()
            
            cifs_exp_dt = dict(cifs_exp_res)
            cifs_exp_rd = cifs_exp_dt['records']
            
            for i in cifs_exp_rd:
                cifs_exp = dict(i)
                name = cifs_exp['name']
                cifs_exp_name.append(name) 
            
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
            
        if cifs_exp_name is False:
            print("No export policy created for cifs protocol with name tag of 'default'")
            crt = input("Would you like to create default export policy with cifs protocol rule?(y/n):")
            if crt == 'y':
                exp_name = "default"
                crt_exp(exp_name, headers)
            elif crt == "n":
                print("You need to create export policy and rule manaul, then re-run this script")
            else:
                print("Invalid Input, re-run script")
                sys.exit(1)
        print()
        exp_name = input("Select one of the export policy:"+str(cifs_exp_name)+": ")
        
        if exp_name in cifs_exp_name:
        
            SecStyle = "ntfs"
            
            crt_vol(volume_size, SecStyle, headers)
            
        else:
            
            print("Invalid Export policy Input, re-run script")
            sys.exit(1)
        
        crt_share(svm_uuid, headers)     
            
    
    else:
        print("Invalid protocal, should be nfs, cifs or multi")
        sys.exit()
        
