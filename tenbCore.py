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

def post_query(api_keys,url,payload):
    headers = {
    'accept': "application/json",
    'X-APIKeys': api_keys
    }
    response = requests.request("POST", url, headers=headers, json=payload)
    try:
        decoded = json.loads(response.text)
        return decoded
    except Exception as e:
        return {"exception":e}

def vulns_export(api_keys,filters,num_assets):
    url="https://cloud.tenable.com/vulns/export"
    payload = {
        "filters":filters,
        "num_assets": num_assets
    }
    decoded = post_query(api_keys,url,payload)
    export_uuid=decoded["export_uuid"]
    print("Export uuid = "+export_uuid)
    return export_uuid

def vulns_export_status(api_keys,export_uuid):
    url="https://cloud.tenable.com/vulns/export/"+export_uuid+"/status"
    decoded=get_query(api_keys,url,{})
    return decoded

def download_vuln_chunk(api_keys,export_uuid,chunk_id):
    url="https://cloud.tenable.com/vulns/export/"+export_uuid+"/chunks/"+chunk_id
    decoded=get_query(api_keys,url,{})
    return decoded

def check_and_download_vuln_chunks(api_keys,filters,num_assets):
    export_uuid=vulns_export(api_keys,filters,num_assets)
    ready=0
    while ready==0:
        decoded=vulns_export_status(api_keys,export_uuid)
        status=decoded["status"]
        print("Job status = "+status)
        if status=="FINISHED":
            ready=1
            return_results=[]
            #print(decoded["chunks_available"])
            for chunk in decoded["chunks_available"]:
                print("Downloading chunk "+str(chunk))
                chunk_results=download_vuln_chunk(api_keys,export_uuid,str(chunk))
                for item in chunk_results:
                    return_results.append(item)
                time.sleep(5)
        time.sleep(5)
    return return_results


def list_scans(api_keys):
    url = "https://cloud.tenable.com/scans"
    querystring={}
    results_json=get_query(api_keys,url,querystring)
    return results_json

def export_workbench(api_keys,querystring):
    url = "https://cloud.tenable.com/workbenches/export"
    decoded = get_query(api_keys,url,querystring)
    myfile=str(decoded['file'])
    print("Export file = "+myfile)
    return myfile

def check_workbench(api_keys,myfile):
    url = "https://cloud.tenable.com/workbenches/export/"+myfile+"/status"
    decoded = get_query(api_keys,url,{})
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
            print("downloading workbench to "+results_file)
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
