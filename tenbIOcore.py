import requests
import json
import time
import os
import csv
import glob
import operator
import socket
import warnings
import sys
from datetime import datetime
from datetime import timedelta
import utilities as ut
import pandas as pd
warnings.filterwarnings("ignore")

'''
Functions that interface with the raw REST APIs
'''

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

def delete_query(api_keys,url):
	headers = {
	'accept': "application/json",
	'X-APIKeys': api_keys
	}
	response = requests.request("DELETE", url, headers=headers)
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

def put_query(api_keys,url,payload):
	headers = {
	'accept': "application/json",
	'X-APIKeys': api_keys
	}
	response = requests.request("PUT", url, headers=headers, json=payload)
	return response.text


'''
Asset Functions
'''

def list_workbenches_assets(api_keys,querystring):
	url = "https://cloud.tenable.com/workbenches/assets"
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_workbenches_vulnerabilities(api_keys,querystring):
	url = "https://cloud.tenable.com/workbenches/vulnerabilities"
	results_json=get_query(api_keys,url,querystring)
	return results_json

def get_asset_count(api_keys,payload):
	decoded=search_assets(api_keys,payload)
	asset_count=decoded["pagination"]["total"]
	return asset_count

def list_asset_filters(api_keys,payload):
	url="https://cloud.tenable.com/filters/workbenches/assets"
	decoded = post_query(api_keys,url,payload)
	return decoded

def search_assets(api_keys,payload):
	url="https://cloud.tenable.com/api/v3/assets/search"
	decoded = post_query(api_keys,url,payload)
	return decoded

def list_assets(api_keys):
	url = "https://cloud.tenable.com/assets"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def get_asset_details(api_keys,asset_uuid):
	url = "https://cloud.tenable.com/assets/"+asset_uuid
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def delete_bulk_assets(api_keys,payload):
	url="https://cloud.tenable.com/api/v2/assets/bulk-jobs/delete"
	decoded = post_query(api_keys,url,payload)
	return decoded

def update_acr_scores(api_keys,asset_lst,acr_score):
	url="https://cloud.tenable.com/api/v2/assets/bulk-jobs/acr"
	payload=[
		{
			"asset":asset_lst,
			"acr_score":acr_score
		}
	]
	response=post_query(api_keys,url,payload)

def assets_export(api_keys,payload):
	url="https://cloud.tenable.com/assets/export"
	decoded = post_query(api_keys,url,payload)
	try:
		export_uuid=decoded["export_uuid"]
	except:
		print(decoded)
		sys.exit("No export_uuid found for this filter condition")
	print("\nExporting asset data")
	print("Export uuid = "+export_uuid)
	return export_uuid

def assets_export_status(api_keys,export_uuid):
	url="https://cloud.tenable.com/assets/export/"+export_uuid+"/status"
	decoded=get_query(api_keys,url,{})
	return decoded

def download_assets_chunk(api_keys,export_uuid,chunk_id):
	url="https://cloud.tenable.com/assets/export/"+export_uuid+"/chunks/"+chunk_id
	decoded=get_query(api_keys,url,{})
	return decoded

def check_and_download_assets_chunks(api_keys,payload,results_file):
	export_uuid=assets_export(api_keys,payload)
	ready=0
	#time.sleep(5)
	while ready==0:
		decoded=assets_export_status(api_keys,export_uuid)
		#print(decoded)
		status=decoded["status"]
		print("Job status = "+status)
		if status=="FINISHED":
			ready=1
			return_results=[]
			print("Chunks available for download = "+str(decoded["chunks_available"]))
			for chunk in decoded["chunks_available"]:
				print("Downloading chunk "+str(chunk))
				chunk_results=download_assets_chunk(api_keys,export_uuid,str(chunk))
				for item in chunk_results:
					return_results.append(item)
				time.sleep(5)
		elif status=="ERROR":
			sys.exit("\nProblem with export")
		time.sleep(5)
	print("Saving results to "+results_file)
	with open(results_file,'w') as outfile:
		json.dump(return_results,outfile)
	return return_results

# ------- End Assets Functions

'''
Vulnerability Functions
'''

def search_findings(api_keys,payload):
	url="https://cloud.tenable.com/api/v3/findings/vulnerabilities/host/search"
	decoded = post_query(api_keys,url,payload)
	return decoded

def get_vulnerability_count(api_keys,querystring):
	decoded=list_workbenches_vulnerabilities(api_keys,querystring)
	vuln_count=decoded["total_vulnerability_count"]
	return vuln_count

def list_vuln_filters(api_keys,payload):
	url="https://cloud.tenable.com/filters/workbenches/vulnerabilities"
	decoded = post_query(api_keys,url,payload)
	return decoded


def list_plugin_outputs(api_keys,plugin_id):
	url = "https://cloud.tenable.com/workbenches/vulnerabilities/"+plugin_id+"/outputs"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def search_vuln_findings(api_keys,payload):
	url = "https://cloud.tenable.com/api/v3/findings/vulnerabilities/host/search"
	results_json=post_query(api_keys,url,payload)
	return results_json

def vulns_export(api_keys,payload):
	url="https://cloud.tenable.com/vulns/export"
	decoded = post_query(api_keys,url,payload)
	try:
		export_uuid=decoded["export_uuid"]
	except:
		print(decoded)
		sys.exit("No export_uuid found for this filter condition")
	print("\nExporting vulnerability data")
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

def check_and_download_vuln_chunks(api_keys,payload,results_file):
	export_uuid=vulns_export(api_keys,payload)
	ready=0
	while ready==0:
		decoded=vulns_export_status(api_keys,export_uuid)
		status=decoded["status"]
		print("Job status = "+status)
		if status=="FINISHED":
			ready=1
			return_results=[]
			print("Chunks available for download = "+str(decoded["chunks_available"]))
			for chunk in decoded["chunks_available"]:
				print("Downloading chunk "+str(chunk))
				chunk_results=download_vuln_chunk(api_keys,export_uuid,str(chunk))
				for item in chunk_results:
					return_results.append(item)
				time.sleep(5)
		time.sleep(5)
	print("Saving results to "+results_file)
	with open(results_file,'w') as outfile:
		json.dump(return_results,outfile)
	return return_results

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

# ------- End Vulnerability Functions

'''
Scan Functions
'''

def list_scans(api_keys):
	url = "https://cloud.tenable.com/scans"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_scanners(api_keys):
	url = "https://cloud.tenable.com/scanners"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_scan_details(api_keys,uuid):
	url = "https://cloud.tenable.com/scans/"+uuid
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def get_scan_host_count(api_keys,uuid):
	url = "https://cloud.tenable.com/scans/"+uuid
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	scan_start=results_json['info']['scan_start']
	scan_end=results_json['info']['scan_end']
	#schedule_uuid=results_json['info']['schedule_uuid']
	if 'hosts' in results_json:
		hosts=results_json["hosts"]
		host_count=len(hosts)
	else:
		host_count=-1
		#print(results_json)
	return host_count,scan_start,scan_end


# ------- End Scan Functions

'''
Permissions Functions
'''

def list_access_groups(api_keys):
	url = "https://cloud.tenable.com/v2/access-groups"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_permissions(api_keys):
	url = "https://cloud.tenable.com/api/v3/access-control/permissions"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_user_permissions(api_keys,uuid):
	url = "https://cloud.tenable.com/api/v3/access-control/permissions/users/"+uuid
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json


def list_users(api_keys):
	url = "https://cloud.tenable.com/users"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_groups(api_keys):
	url = "https://cloud.tenable.com/groups"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_access_groups(api_keys):
	url = "https://cloud.tenable.com/v2/access-groups"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def get_access_group_details(api_keys,id):
	url = "https://cloud.tenable.com/v2/access-groups/"+id
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def delete_access_group(api_keys,id):
	url = "https://cloud.tenable.com/v2/access-groups/"+id
	querystring={}
	results_json=delete_query(api_keys,url)
	return results_json

def create_group(api_keys,group_name):
	url = "https://cloud.tenable.com/groups"
	payload={"name":group_name}
	results_json=post_query(api_keys,url,payload)
	return results_json

def update_permissions(api_keys,uuid,name,actions,objects,subjects):
	url = "https://cloud.tenable.com/api/v3/access-control/permissions/"+uuid
	payload={
	'actions':actions,
	'objects':objects,
	'subjects':subjects,
	'name':name
	}
	results_json=put_query(api_keys,url,payload)
	return results_json

# ------- End Permission Functions

'''
Tag Functions
'''

def list_tag_values(api_keys,tag_cat):
#	url = "https://cloud.tenable.com/tags/values?f=category_name%3Amatch%3AUQ%20Owner"
	url = "https://cloud.tenable.com/tags/values?f=category_name%3Aeq%3A" + tag_cat
	headers = {
	'accept': "application/json",
	'X-APIKeys': api_keys
	}
	response = requests.request("GET", url, headers=headers)
	try:
		decoded = json.loads(response.text)
		return decoded
	except Exception as e:
		return {"exception":e}

def get_tag_uuid(api_keys,tag_cat,tag_value):
	decoded=list_tag_values(api_keys,tag_cat)
	uuid=""
	for x in decoded["values"]:
		if x["value"]==tag_value:
			uuid=x["uuid"]
	return uuid

def create_tag_value(api_keys,payload):
	url="https://cloud.tenable.com/tags/values"
	decoded = post_query(api_keys,url,payload)
	return decoded

def update_tag_value(api_keys,payload,uuid):
	url="https://cloud.tenable.com/tags/values/"+uuid
	decoded = put_query(api_keys,url,payload)
	return decoded

# ------- End Tag Functions

'''
Compliance Functions
'''

def compliance_export(api_keys,payload):
	url="https://cloud.tenable.com/compliance/export"
	decoded = post_query(api_keys,url,payload)
	try:
		export_uuid=decoded["export_uuid"]
	except:
		print(decoded)
		sys.exit("No export_uuid found for this filter condition")
	print("\nExporting compliance data")
	print("Export uuid = "+export_uuid)
	return export_uuid

def compliance_export_status(api_keys,export_uuid):
	url="https://cloud.tenable.com/compliance/export/"+export_uuid+"/status"
	decoded=get_query(api_keys,url,{})
	return decoded

def download_compliance_chunk(api_keys,export_uuid,chunk_id):
	url="https://cloud.tenable.com/compliance/export/"+export_uuid+"/chunks/"+chunk_id
	decoded=get_query(api_keys,url,{})
	return decoded

def check_and_download_compliance_chunks(api_keys,payload,results_file):
	export_uuid=compliance_export(api_keys,payload)
	ready=0
	while ready==0:
		decoded=compliance_export_status(api_keys,export_uuid)
		status=decoded["status"]
		print("Job status = "+status)
		if status=="FINISHED":
			ready=1
			return_results=[]
			print("Chunks available for download = "+str(decoded["chunks_available"]))
			for chunk in decoded["chunks_available"]:
				print("Downloading chunk "+str(chunk))
				chunk_results=download_compliance_chunk(api_keys,export_uuid,str(chunk))
				for item in chunk_results:
					return_results.append(item)
				time.sleep(5)
		time.sleep(5)
	print("Saving results to "+results_file)
	with open(results_file,'w') as outfile:
		json.dump(return_results,outfile)
	return return_results

# ------- End Compliance Functions

'''
Miscellaneous functions
'''
def calculate_fix_times(input_file,filters):
	# takes a standard export file of fixed vulns
	# and returns a json file showing the fix times
	decoded=ut.read_json_file(input_file)
	count=0
	results=[]
	for x in decoded:
		ffound=x["first_found"]
		lfound=x["last_found"]
		lfixed=x["last_fixed"]
		ipv4=x["asset"]["ipv4"]
		uuid=x["asset"]["uuid"]
		pid=x["plugin"]["id"]
		severity=x["severity"]
		ttfix=ut.date_diff(ffound,lfixed)
		fix_date=lfixed.split("T")[0]
		mydct={'date':pd.to_datetime(fix_date),'total':ttfix,severity:ttfix,'pid':pid,'ipv4':ipv4}
		append_result=0
		if len(filters)==0:
			append_result=1
		else: # filter applied so test condition
			if 'exploitable' in filters:
				if x["plugin"]["exploit_available"]==filters['exploitable']:
					append_result=1
		if append_result==1:
			results.append(mydct)
	return results
