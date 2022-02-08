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
    print("List of Aggregates on ",cluster)
    print("==========================================")
    r=0
    tab = tt.Texttable()
    header = ['Aggr name','Available space(GB)']
    tab.header(header)
    tab.set_cols_width([25,25])
    tab.set_cols_align(['c','c'])

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
            #row = [clus]
            tab.add_row([aggr_name,space_convert])
            tab.set_cols_width([25,25])
            tab.set_cols_align(['c','c'])
        #print("Number of Storage VMs on this NetApp cluster :{}".format(ctr))
    setdisplay = tab.draw()
    print(setdisplay)
        

        
#def list_svm(cluster: str, dsktype: str, headers_inc: str) -> None:
#    """Lists the VServers"""



    
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
    
    #tier = ARGS.dskt
    
    if ARGS.env == 'prod':
        if ARGS.dskt == 'sata':
            dsktype = ['sas','ssd','sata']
        else:
            dsktype = ['sas','ssd']
        ARGS.env = 'pfsx'
        clstr_name = find_clstr(ARGS.s, ARGS.env)
        for clstr in clstr_name:
                aggr_list = list_aggregate(clstr,dsktype,headers)
    elif ARGS.env == 'nprod':
        if (ARGS.dskt == 'sas' or ARGS.dskt == 'ssd'):
            dsktype = ['sas','ssd','sata']
        else:
            dsktype = ['sata']
        ARGS.env = 'sfsx'
        clstr_name = find_clstr(ARGS.s, ARGS.env)
        for clstr in clstr_name:
                aggr_list = list_aggregate(clstr,dsktype,headers)
    else:
        print()
        print("-env value invalid, it should be prod or nprod")
        sys.exit(1)
        
    hostname = ARGS.host 
    ip_add = socket.gethostbyname(hostname).split('.')
    subnet = '.'.join(ip_add[0:3])
    
    
    