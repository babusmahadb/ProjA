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


def get_svms(cluster: str, headers_inc: str):
    """ Get SVMs"""
    url = "https://{}/api/svm/svms".format(cluster)
    response = requests.get(url, headers=headers_inc, verify=False)
    return response.json()


def get_key_svms(cluster: str, svm_name: str, headers_inc: str):
    """Get SVM Key"""
    tmp = dict(get_svms(cluster, headers_inc))
    svms = tmp['records']
    for i in svms:
        if i['name'] == svm_name:
            return i['uuid']
        return None


def get_vols(cluster: str, headers_inc: str):
    """ Get Volumes"""
    url = "https://{}/api/storage/volumes/".format(cluster)
    response = requests.get(url, headers=headers_inc, verify=False)
    return response.json()


def get_size(volume_size):
    """Convert MBs to Bytes"""
    tmp = int(volume_size) * 1024 * 1024
    return tmp


def check_job_status(cluster: str, job_status: str, headers_inc: str):
    """ Check job status"""
    #a = job_status['state']
    type(job_status)
    
    print("inside fun", job_status) 
    if job_status['state'] == "failure":
        print(
            "Volume creation failed due to :{}".format(
                job_status['message']))
    elif job_status['state'] == "success":
        print("Volume created successfully")
    else:
        job_status_url = "https://{}/api/cluster/jobs/{}".format(
            cluster, job_status['uuid'])
        job_response = requests.get(
            job_status_url, headers=headers_inc, verify=False)
        job_status = job_response.json()
        check_job_status(cluster, job_status, headers_inc)

#def show_aggregate(cluster: str):


    
    
    
def make_volume(cluster: str, volume_name: str, svm_name: str, aggr_name: str, volume_size, headers_inc: str):
    """Module to create a volume"""
    
    url = "https://{}/api/storage/volumes".format(cluster)
    #payload = {
    #    "aggregates.name": [aggr_name],
    #    "svm.name": svm_name,
    #    "name": volume_name,
    #    "size": v_size
    #}
    #
    #response = requests.post(
    #    url,
    #    headers=headers_inc,
    #    json=payload,
    #    verify=False)
    #url_text = response.json()
    #job_status = "https://{}/{}".format(cluster,
    #                                    url_text['job']['_links']['self']['href'])
    #job_response = requests.get(job_status, headers=headers_inc, verify=False)
    #job_status = job_response.json()
    #check_job_status(cluster, job_status, headers_inc)

    dataobj = {}
    tmp1 = {"name": svm_name}
    dataobj['svm'] = tmp1
    #print()
    ##show_aggregate(cluster, headers_inc)
    #print()
    #aggrname = input(
    #    "Enter the name of the Aggregate on which the volume needs to be created:- ")
    tmp2 = [{"name": aggr_name}]
    dataobj['aggregates'] = tmp2
    #print()
    #volname = input("Enter the name of the Volume:- ")
    dataobj['name'] = volume_name
    #print()
    #vol_size = input("Enter the size of the Volume in MB:- ")
    tmp3 = get_size(volume_size)
    dataobj['size'] = tmp3
    #print()
    #voltype = input("Enter the Volume Type[rw/dp]:- ")
    dataobj['type'] = "rw"
    print()
    styletype = input("Enter the Volume Style Type[flexvol]:- ")
    dataobj['style'] = styletype
    print()
    #autosize = input("Would you like to enable Autosize (y/n): ")
    #if autosize == 'y':
    #    print("Enter the following Details")
    #    grow_threshold = input("grow_threshold?:- ")
    #    maximum = input("maximum?:- ")
    #    minimum = input("minimum?:- ")
    #    mode = input("mode?:- ")
    #    shrink_threshold = input("shrink_threshold?:- ")
    #    autosizejson = {
    #        "grow_threshold": grow_threshold,
    #        "maximum": maximum,
    #        "minimum": minimum,
    #        "mode": mode,
    #        "shrink_threshold": shrink_threshold}
    #    dataobj['autosize'] = autosizejson
    #print()
    #efficiency = input("Would you like to enable Efficiency (y/n): ")
    #if efficiency == 'y':
    #    print("Enter the following Details")
    #    compaction = input("compaction?:- ")
    #    compression = input("compression?:- ")
    #    cross_volume_dedupe = input("cross_volume_dedupe?:- ")
    #    dedupe = input("dedupe?:- ")
    #    policy_name_e = input("Efficiency Policy Name?:- ")
    #    efficiencyjson = {
    #        "compaction": compaction,
    #        "compression": compression,
    #        "cross_volume_dedupe": cross_volume_dedupe,
    #        "dedupe": dedupe,
    #        "policy": {
    #            "name": policy_name_e}}
    #    dataobj['efficiency'] = efficiencyjson
    #print()
    #encryption = input("Would you like to enable Encryption (y/n): ")
    #if encryption == 'y':
    #    print("Enter the following Details")
    #    enabled_encry = input("Enable Encryption ?:- ")
    #    encryptionjson = {"enabled": bool(enabled_encry), "status": {}}
    #    dataobj['encryption'] = encryptionjson
    #print()
    #files = input("Would you like to enable Max File Count (y/n): ")
    #if files == 'y':
    #    print("Enter the following Details")
    #    maximum_files = input("Max File Count?:- ")
    #    filesjson = {"maximum": maximum_files}
    #    dataobj['files'] = filesjson
    #print()
    nas = input("Would you like to enable NAS parameters (y/n): ")
    if nas == 'y':
        print("Enter the following Details")
        export_policy_name = input("Enter new policy name for share:- ")
        export_policy_rule = input("Enter clientmatch name for share[0.0.0.0/0]:- ")
        create_export_policy(cluster,export_policy_name,export_policy_rule,svm_name,headers_inc)
        path = input("path?:- ")
        security_style = input("security_style?:- ")
        unix_permissions = input("unix_permissions?:- ")
        nasjson = {
            "export_policy": {
                "name": export_policy_name},
            "path": path,
            "security_style": security_style,
            "unix_permissions": unix_permissions}
        dataobj['efficiency'] = nasjson
    print()
    qos = input("Would you like to enable QoS (y/n): ")
    if qos == 'y':
        print("Enter the following Details")
        max_throughput_iops = input("max_throughput_iops?:- ")
        max_throughput_mbps = input("max_throughput_mbps?:- ")
        min_throughput_iops = input("min_throughput_iops?:- ")
        qosname = input("qosname?:- ")
        qosjson = {
            "policy": {
                "max_throughput_iops": max_throughput_iops,
                "max_throughput_mbps": max_throughput_mbps,
                "min_throughput_iops": min_throughput_iops,
                "name": qosname}}
        dataobj['qos'] = qosjson
    print()
    quota = input("Would you like to enable Quota (y/n): ")
    if quota == 'y':
        print("Enter the following Details")
        enable_quota = input("enable_quota?:- ")
        quotajson = {"enabled": bool(enable_quota)}
        dataobj['quota'] = quotajson
    print(dataobj)
    url = "https://{}/api/storage/volumes/?return_timeout=30".format(cluster)
    try:
        response = requests.post(
            url,
            headers=headers_inc,
            json=dataobj,
            verify=False)
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
    job_status = "https://{}{}".format(cluster,
                                       url_text['job']['_links']['self']['href'])
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
    check_job_status(cluster, job_status, headers_inc )


def create_export_policy(
        cluster: str,
        export_policy_name: str,
        export_policy_rule: str,
        svm_name: str,
        headers_inc: str):
    """Create Export Policy"""
    url = "https://{}/api/protocols/nfs/export-policies".format(cluster)
    #svm_uuid = get_key_svms(cluster, svm_name, headers_inc)
    payload = {
        "name": export_policy_name,
        "rules": [
            {
                "clients": [
                    {
                        "match": export_policy_rule
                    }
                ],
                "protocols": [
                    "any"
                ],
                "ro_rule": [
                    "any"
                ],
                "rw_rule": [
                    "any"
                ]}],
        "svm.uuid": svm_uuid
    }
    response = requests.post(
        url,
        headers=headers_inc,
        json=payload,
        verify=False)
        
        
def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""

    parser = argparse.ArgumentParser(
        description="This script will create an ONTAP volume in an SVM",
    )
    parser.add_argument(
        "-c", "--cluster", required=True, help="API server IP:port details"
    )
    parser.add_argument(
        "-v",
        "--volume_name",
        required=True,
        help="Name of the volume that needs to be created.")
    parser.add_argument(
        "-vs", "--svm_name", required=True, help="svm name"
    )
    parser.add_argument(
        "-a", "--aggr_name", required=True, help="Aggregate Name"
    )
    parser.add_argument(
        "-sz", "--volume_size", required=True, help="Volume Size"
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

    make_volume(
        ARGS.cluster,
        ARGS.volume_name,
        ARGS.svm_name,
        ARGS.aggr_name,
        ARGS.volume_size,
        headers)