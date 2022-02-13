"""
ONTAP REST API Sample Scripts

Purpose: Script to list volumes properties using ONTAP REST API.

Usage: csa.py [-h] -s SITE_CODE -env PROD [-u API_USER] [-p API_PASS]
"""

import pandas as pd
import openpyxl as xl
import urllib3 as ur
import socket
import base64
import argparse
from getpass import getpass
import logging
import texttable as tt
import requests
import json

import sys

ur.disable_warnings()

def find_clstr(site: str, envir: str):
    """Get cluster info from inventory using user inputs"""
    
    wb = xl.load_workbook(r'C:\\Users\\Administrator.DEMO\\Documents\\GitHub\\ProjA\\projclstrs.xlsx')

#active worksheet data
    ws = wb.active    

    output = []
    for i in range(1, ws.max_row + 1):
        for j in range(1, ws.max_column + 1):
            if site in ws.cell(i,j).value:
                #print("found")
                val = ws.cell(i,j).value   
                if envir in val:
                   op = ''.join(val)
                   output.append(op)

    return output
    
def list_aggregate(cluster: str, dsktype: str, headers_inc: str) -> None:
    """Lists the Aggregate"""
    print()
    #print("List of Aggregates on ",cluster)
    #print("==========================================")
    r=0
    tab = tt.Texttable()
    header = ['Cluster Name','VServer Name','Aggr name','Available space(GB)']
    tab.header(header)
    tab.set_cols_width([25,25,25,25])
    tab.set_cols_align(['c','c','c','c'])

    for dsk in dsktype:
        url = "https://{}/api/storage/aggregates?name=*{}*".format(cluster,dsk)
        try:
            response = requests.get(url, headers=headers_inc, verify=False)
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print(err)
            sys.exit(1)
        tmp = dict(response.json())
        aggr = tmp['records']

        for i in aggr:
            r = r + 1
            aggr_uuid = i['uuid']
            url = "https://{}/api/storage/aggregates/{}".format(cluster,aggr_uuid)
            try:
                response = requests.get(url, headers=headers_inc, verify=False)
            except requests.exceptions.HTTPError as err:
                print(err)
                sys.exit(1)
            except requests.exceptions.RequestException as err:
                print(err)
                sys.exit(1)
            tmp = dict(response.json())
            tmp2 = dict(tmp['space'])
            tmp3 = dict(tmp2['block_storage'])
            avail = tmp3['available']
            space_convert=(((int(avail)/1024)/1024)/1024)
            aggr_name = i['name']
            svm_name = list_svm(cluster, headers)
            tab.add_row([cluster,svm_name,aggr_name,space_convert])
            tab.set_cols_width([25,25,25,25])
            tab.set_cols_align(['c','c','c','c'])
        #print("Number of Storage VMs on this NetApp cluster :{}".format(ctr))
    setdisplay = tab.draw()
    print(setdisplay)
        
def sort_svm(cluster: str, headers_inc: str):
    """Sorts VServers with app condition"""
    apps = ARGS.app
    app_list = ["arch","bkp","cdp","cf0","dap","ddb","dmz","dp01","dpt","erp","hd0","mist","nps","pap","pdb","rdb","san","sris","tap","tdb","test","vm0"]
    ctr = 0
    sort_row = []
    tmp = dict(get_vservers(cluster, headers_inc))
    vservers = tmp['records']
    
    for i in vservers:
        ctr = ctr + 1
        if apps in app_list:
            sort_row = ["svm_for_"+apps]
        else:
            print("provide valid -app value, it must be one of ",app_list)
            sys.exit(1)
    return sort_row 

    
def list_svm(cluster: str, headers_inc: str):
    """Lists the VServers"""
    hostname = ARGS.host 
    services = ARGS.proto
     
    host_ip_add = socket.gethostbyname(hostname).split('.')
    host_subnet = '.'.join(host_ip_add[0:3])  
    ctr = 0
    tmp = dict(get_vservers(cluster, headers_inc))
    vservers = tmp['records']
    
    row = []
    for i in vservers:
        ctr = ctr + 1
        if services == 'nfs':
            clus = i['name']
            svm_ip_add = socket.gethostbyname(clus).split('.')
            svm_subnet = '.'.join(svm_ip_add[0:3])
            if host_subnet == svm_subnet:
                row = [clus+"*"]
                return row
            srt = sort_svm(cluster, headers_inc)
            clus = clus + srt
            row = [clus]
        elif services == 'cifs':
            rcd_dt = dict(i)
            svm_rd = rcd_dt['svm']
            svm_dt = dict(svm_rd)
            clus = svm_dt['name']
            srt = sort_svm(cluster, headers_inc)
            clus = clus + srt
            row=[clus]
        else:
            srt = sort_svm(cluster, headers_inc)
            clus = clus + srt
            row=[clus]
            
        
    return row
    
def get_vservers(cluster: str, headers_inc: str):
    """ Get vServer"""
    services = ARGS.proto
    
    if services == 'nfs':
        url = "https://{}/api/svm/svms?{}.enabled=true".format(cluster,services)
        try:
            response = requests.get(url, headers=headers_inc, verify=False)
            print(response.json())
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print(err)
            sys.exit(1)
    elif services == 'cifs':
        url = "https://{}/api/protocols/{}/services?enabled=true".format(cluster,services)
        
        try:
            response = requests.get(url, headers=headers_inc, verify=False)
               
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print(err)
            sys.exit(1)
    elif services == 'iscsi':
        url = "https://{}/api/protocols/san/{}/services?enabled=true".format(cluster,services)
        try:
            response = requests.get(url, headers=headers_inc, verify=False)
        except requests.exceptions.HTTPError as err:
            print(err)
            sys.exit(1)
        except requests.exceptions.RequestException as err:
            print(err)
            sys.exit(1)
    else:
        print()
        print(" Enter Valid protocol, should be nfs, cifs or iscsi")
        sys.exit(1)
    return response.json()
    
def parse_args() -> argparse.Namespace:
    """Parse the command line arguments from the user"""

    parser = argparse.ArgumentParser(
        description="This script will list volumes in a SVM")
    parser.add_argument(
        "-s", required=True, help="It should be valide site code like uslv,demu,usto so on.."
                        )
    parser.add_argument(
        "-env", required=True, help="It should be prod or nprod"  
                        )
    parser.add_argument(
        "-host", required=True, help="Valid Servername"  
                        )
    parser.add_argument(
        "-app", required=True, help="App name or purpose of provisioning like arch,bkp,cdp,cf0,pdb,ddb,dmz so on.."  
                        )                    
    parser.add_argument(
        "-proto", required=True, help="Valid protocal value of nfs,cifs,iscsi,fc"  
                        )                        
    parser.add_argument(
        "-dskt", required=False, help="It should be sas,ssd or sata"  
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

#def get_volumes(cluster: str, svm_name: str, volume_name: str, headers_inc: str):
#    """Get Volumes"""
#    url = "https://{}/api/storage/volumes/?svm.name={}".format(cluster, volume_name)
#    response = requests.get(url, headers=headers_inc, verify=False)
#    return response.json()

                
                
if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] [%(levelname)5s] [%(module)s:%(lineno)s] %(message)s",
    )
    ARGS = parse_args()
    BASE_64_STRING = base64.encodebytes(
        ('%s:%s' %
         (ARGS.api_user, ARGS.api_pass)).encode()).decode().replace('\n', '')
    
    headers = {
        'authorization': "Basic %s" % BASE_64_STRING,
        'content-type': "application/json",
        'accept': "application/json"
    }
    
    
    
    if ARGS.env == 'prod':
        if ARGS.dskt == 'sata':
            dsktype = ['sas','ssd','sata']
        else:
            dsktype = ['sas','ssd']
        ARGS.env = 'pfsx'
        clstr_name = find_clstr(ARGS.s, ARGS.env)
        for clstr in clstr_name:
                aggr_list = list_aggregate(clstr,dsktype,headers)
                #svm_list = list_svm(clstr, headers)
    elif ARGS.env == 'nprod':
        if (ARGS.dskt == 'sas' or ARGS.dskt == 'ssd'):
            dsktype = ['sas','ssd','sata']
        else:
            dsktype = ['sata']
        ARGS.env = 'sfsx'
        clstr_name = find_clstr(ARGS.s, ARGS.env)
        for clstr in clstr_name:
                aggr_list = list_aggregate(clstr,dsktype,headers)
                #svm_list = list_svm(clstr, headers)
    else:
        print()
        print("-env value invalid, it should be prod or nprod")
        sys.exit(1)
        

    
    
    
    #disp_vservers(ARGS.cluster, headers)
    