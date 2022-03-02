import requests
import json
import time
import os
import csv
import glob
import operator
import socket
import warnings
from datetime import datetime
warnings.filterwarnings("ignore")

def read_keys(keys_file,instance):
    f=open(keys_file,"r")
    keys=json.load(f)
    tio_AK=keys[instance]["tio_AK"]
    tio_SK=keys[instance]["tio_SK"]
    api_keys="accessKey="+tio_AK+";secretKey="+tio_SK
    return api_keys

def get_query(api_keys,url,querystring):
    headers = {
    'accept': "application/json",
    'X-APIKeys': api_keys
    }
    response = requests.request("GET", url, headers=headers, params=querystring)
    try:
        decoded = json.loads(response.text)
        return decoded
    except Exception as e:
        return {"exception":e}

def list_scans(api_keys):
    url = "https://cloud.tenable.com/scans"
    querystring={}
    results_json=get_query(api_keys,url,querystring)
    return results_json

def export_workbench(api_keys,querystring):
    url = "https://cloud.tenable.com/workbenches/export"
    headers = {
    'accept': "application/json",
    'X-APIKeys': api_keys
    }
    response = requests.request("GET", url, headers=headers, params=querystring)
    decoded = json.loads(response.text)
    #print(decoded)
    myfile=str(decoded['file'])
    return myfile

def check_workbench(api_keys,myfile):
    url = "https://cloud.tenable.com/workbenches/export/"+myfile+"/status"
    headers = {
    'accept': "application/json",
    'X-APIKeys': api_keys
    }
    response = requests.request("GET", url, headers=headers)
    decoded = json.loads(response.text)
    return decoded['status']

def download_workbench(api_keys,myfile):
    url = "https://cloud.tenable.com/workbenches/export/"+myfile+"/download"
    headers = {
    'accept': "application/json",
    'X-APIKeys': api_keys
    }
    response = requests.request("GET", url, headers=headers)
    return response.text

def check_and_download_workbench(api_keys,filter,results_file,report_type):
    querystring={
    "format":report_type,
    "report":"vulnerabilities",
    "chapter":"vuln_by_asset",
    "filter.search_type":"and",
    "all_fields":"full"
    }
    querystring.update(filter)
    myfile=export_workbench(api_keys,querystring)
    ready=0
    while ready==0:
        status=check_workbench(api_keys,myfile)
        print("Job status = "+status)
        if status=="ready":
            ready=1
            print("downloading workbench.....")
            resp_text=download_workbench(api_keys,myfile)
            print("download complete")
        time.sleep(5)
    f = open(results_file,"w")
    f.write(resp_text)
    f.close()


def get_vuln_filters(api_keys):
    url = "https://cloud.tenable.com/filters/workbenches/vulnerabilities"
    querystring={}
    results_json=get_query(api_keys,url,querystring)
    return results_json

def hostIP_html_vuln_report(api_keys,host_ip,results_file):
    filter={
    "filter.0.filter":"host.target",
    "filter.0.quality":"eq",
    "filter.0.value":host_ip,
    }
    report_type="html"
    check_and_download_workbench(api_keys,filter,results_file,report_type)
