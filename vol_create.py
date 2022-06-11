
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


def check_job(job_status: str, headers_inc: str):
    """ Check job status"""
    print()

    if job_status['state'] == "failure":
        print(bcolors.WARNING,"Volume creation failed due to :"+bcolors.ENDC+"{}".format(job_status['message']))
    elif job_status['state'] == "success":
        if path == "":
            print("Volume "+bcolors.HEADER,vol_name,bcolors.ENDC+" of "+bcolors.HEADER,vol_size.upper(),bcolors.ENDC+" created successfully.")
        else:    
            print("Volume "+bcolors.HEADER,vol_name,bcolors.ENDC+" of "+bcolors.HEADER,vol_size.upper(),bcolors.ENDC+" created successfully. Junction path is "+bcolors.OKGREEN,path,bcolors.ENDC+" .")
    else:
        job_status_url = "https://{}/api/cluster/jobs/{}".format(clus_name, job_status['uuid'])
        job_response = requests.get(job_status_url, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job( job_status, headers_inc)

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
    dpv = "_mir"
    if dpv in vol_name:
       snapshot_policy = "none"
    else:
        if not snap_list:
            snapshot_policy = "default"
        else:
            print()
            snapshot_policy = input("Pick the snapshot policy for volume "+vol_name+" :"+str(snap_list)+": ")

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
        check_job(job_status, headers_inc)
        
    except requests.exceptions.HTTPError as err:
        print(err)
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(err)
        sys.exit(1)
    

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    
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



def get_exp_id(exp_name: str, headers_inc: str):
    """ Get's Export Policy ID using policy name """

    #print("clus_name,exp_name",clus_name,exp_name)
    exp_id_url = "https://{}/api/protocols/nfs/export-policies/?name={}".format(clus_name,exp_name)
    response = requests.get(exp_id_url, headers=headers_inc, verify=False)
    exp_id_res = response.json()

    exp_id_dt = dict(exp_id_res)
    #print("exp_id_dt",exp_id_dt)
    exp_id_rd = exp_id_dt['records']
    #print("exp_id_rd",exp_id_rd)
    for i in exp_id_rd:
        pid = dict(i)
        #print("pid ",pid)

    expt_id = pid['id']

    return  expt_id


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

        print("Rule for export Policy"+bcolors.OKBLUE,exp_name,bcolors.ENDC+"updated with protocol nfs3 for volume"+bcolors.HEADER,vol_name,bcolors.ENDC+"having access ro/rw/su of sys for client"+bcolors.OKCYAN,host,bcolors.ENDC+"")


def crt_pol_rule(client: str, headers_inc: str):
    """ creates export policy name and rule index 1 """
    anon = "65534"
    #print("exp_name,vol_name,clus_name", exp_name,vol_name,clus_name)
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
    #print("exp_res",exp_res)
    print()
    print("Export policy"+bcolors.OKBLUE,exp_name,bcolors.ENDC+"created for volume"+bcolors.HEADER,vol_name,bcolors.ENDC+"with rule ro/rw/su of sys for clients"+bcolors.OKCYAN,client,bcolors.ENDC+"")
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
    print("Policy"+bcolors.OKBLUE,exp_name,bcolors.ENDC+"created with cifs protocol clientmatch of 0.0.0.0/0")


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

            print("Rule for export Policy"+bcolors.OKBLUE,exp_name,bcolors.ENDC+"updated with protocol nfs3 for volume"+bcolors.HEADER,vol_name,bcolors.ENDC+"having access ro/rw/su of sys for client"+bcolors.OKCYAN,clientlist,bcolors.ENDC+"")

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
    print("CIFS share"+bcolors.OKBLUE,share_name,bcolors.ENDC+"created with path :"+bcolors.OKGREEN,path,bcolors.ENDC+"")



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

def mnt_vol(vol_name: str, headers: str):

    mnt_obj = {
        "nas": {
            "path": path
            }
        }

    mnt_url = "https://{}/api/storage/volumes?name={}".format(clus_name,vol_name)
    response = requests.patch(mnt_url, headers=headers, json=mnt_obj, verify=False)
    mnt_json = response.json()
    print()
        
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
        print("DP volume"+bcolors.HEADER,vol_name,bcolors.ENDC+"mounted, and Junction path is:",bcolors.OKGREEN,path,bcolors.ENDC)
    else:
        print("Volume mount failed",bcolors.FAIL,mnt_chk,bcolors.ENDC)
    print()
    
def check_job_status(cluster: str, job_status: str, failed: str, created: str, creating: str, headers_inc: str):
    """Check Job Status"""
    #print("inside function", failed,created,creating)
    
    if job_status['state'] == "failure":
        print("{}{}".format(failed,bcolors.FAIL,job_status['message'],bcolors.ENDC))
    elif job_status['state'] == "success":
        print(created)
    else:
        print(creating)
        time.sleep(15)
        url_text = '/api/cluster/jobs/' + job_status['uuid']
        job_status = "https://{}/{}".format(cluster, url_text)
        job_response = requests.get(job_status, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status(cluster, job_status, failed, created, creating, headers_inc)
        
        
def crt_estab_snpmir(tgt_clus: str, headers: str):

    dataobj = {}
    src = src_svm+":"+src_vol
    dst = tgt_svm+":"+tgt_vol
    dataobj['source'] = {"path": src}
    dataobj['destination'] = {"path": dst}

    #print(dataobj)

    smc_url = "https://{}/api/snapmirror/relationships/".format(tgt_clus)
    try:
        response = requests.post(smc_url,headers=headers,json=dataobj, verify=False)
    except requests.exceptions.HTTPError as err:
        print(str(err))
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(str(err))
        sys.exit(1)
    smc_res = response.json()
    print()
    url_text = '/api/cluster/jobs/' + smc_res['job']['uuid']
    job_status = "https://{}/{}".format(tgt_clus, url_text)
    job_response = requests.get(job_status, headers=headers, verify=False)
    job_status = job_response.json()
    failed = "SnapMirror creation failed due to :"  
    created = "SnapMirror created successfully between "+src+" and "+dst+"."
    creating = "SnapMirror creation in process...."
    check_job_status(tgt_clus, job_status, failed, created, creating, headers)
    
    sm_url = "https://{}/api/snapmirror/relationships?source.path={}".format(tgt_clus, src)
    response = requests.get(sm_url,headers=headers, verify=False)
    sm_res = response.json()
    #print(sm_res)
    sm_dt = dict(sm_res)
    sm_rd = sm_dt['records']

    if not sm_rd:
        print("Creation of Snapmirror for"+bcolors.FAIL,src,bcolors.ENDC+"failed, refer JOB ID: ", smc_res)
        sys.exit(1)
    for id in sm_rd:
        smuuid = id['uuid']

    dataobj['state'] = "snapmirrored"

    smi_url = "https://{}/api/snapmirror/relationships/{}".format(tgt_clus,smuuid)
    try:
        response = requests.patch(smi_url,headers=headers,json=dataobj, verify=False)
    except requests.exceptions.HTTPError as err:
        print(str(err))
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        print(str(err))
        sys.exit(1)
    smi_res = response.json()
    print()
    url_text = '/api/cluster/jobs/' + smi_res['job']['uuid']
    job_status = "https://{}/{}".format(tgt_clus, url_text)
    job_response = requests.get(job_status, headers=headers, verify=False)
    job_status = job_response.json()
    failed = "SnapMirror initialize failed due to :"  
    created = "SnapMirror initialized successfully between "+src+" and "+dst+"."
    creating = "SnapMirror initializion in process...."
    check_job_status(tgt_clus, job_status, failed, created, creating, headers)
    



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
    typ = "rw"

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
        print(bcolors.FAIL,"Invalid username/password",bcolors.ENDC)
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
    lang = svm_lang
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


    if ( ARGS.proto == "nfs" or ARGS.proto == "multi"):

        exp_name = vol_name+"_ip"

        crt_exp(exp_name, headers)

        SecStyle = "unix"

        crt_vol(volume_size, SecStyle, headers)
         #Language: en_US.UTF-8  #if volume is dp, make sure language is same of source svm value.


    elif ARGS.proto == "cifs":

        #Export Policy: cifs-default or default
        cifs_exp_name = []
        #cifs_exp_url = "https://{}/api/protocols/nfs/export-policies?name=*default*&rules.protocols=cifs&svm.name={}".format(clus_name,svmname)
        cifs_exp_url = "https://{}/api/protocols/nfs/export-policies?name=*default*&rules.protocols=cifs".format(clus_name)
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

        if not cifs_exp_name:
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


    if smirror == "y":

        print()
        peer_clus = input("Enter a Target Cluster name/IP for SnapMirror Configuration: ")
        peer_svm = input("Enter a Target SVM Name: ")
        peer_aggr = input("Enter a Target Aggregate Name: ")
        print()

        typ = "dp"
        lang = svm_lang
        snapshot_policy = "none"
        path = ""

        src_clus = clus_name
        src_svm = svmname
        src_vol = vol_name

        clus_name = peer_clus
        svmname = peer_svm
        aggrname = peer_aggr

        #vol_name = vol_name+"_mir"
        tgt_clus = clus_name
        tgt_svm = svmname
        #tgt_vol = vol_name

        psvmd=get_svm()
        svm_uuid = psvmd[0]
        #svm_lang = psvmd[1]
        #exp_name = vol_name

        aggrname = peer_aggr
        svmname = peer_svm
        #print("tgt_svm, svmname",tgt_svm, svmname)
        svm_tag = svmname.split("-")

        if len(svm_tag) == 0:
           svm_tag = svmname.split("_")
           svm_tag = svm_tag[2]
        else:
           svm_tag = svm_tag[2]


        #if ARGS.volname:
        #   vol_name = ARGS.volname
        #else:
        vol_name = "v_"+svm_tag+"_"+shrproto+"_"+funcgrp.upper()+res

        vol_name = vol_name+"_mir"
        exp_name = vol_name
        tgt_vol = vol_name


        crt_exp(exp_name, headers)

        if (ARGS.proto == "nfs" or ARGS.proto == "multi"):
            SecStyle = "unix"
            crt_vol(volume_size, SecStyle, headers)
            crt_estab_snpmir(tgt_clus, headers)
            path = "/"+vol_name
            mnt_vol(vol_name, headers)
        elif ARGS.proto == "cifs":
            SecStyle = "ntfs"
            crt_vol(volume_size, SecStyle, headers)
            crt_share(svm_uuid, headers)
            crt_estab_snpmir(tgt_clus, headers)
            path = "/"+vol_name
            mnt_vol(vol_name, headers)

        else:
            print("Invalid protocal, should be nfs, cifs or multi")
            sys.exit()



