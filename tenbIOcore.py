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

def update_acr_scores(api_keys,asset_lst,acr_score):
	url="https://cloud.tenable.com/api/v2/assets/bulk-jobs/acr"
	payload=[
		{
			"asset":asset_lst,
			"acr_score":acr_score
		}
	]
	response=post_query(api_keys,url,payload)

def list_scans(api_keys):
	url = "https://cloud.tenable.com/scans"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_workbenches_assets(api_keys,querystring):
	url = "https://cloud.tenable.com/workbenches/assets"
	results_json=get_query(api_keys,url,querystring)
	return results_json

def exposure_score_assets(api_keys,querystring):
	url = "https://cloud.tenable.com/lumin/widgets/exposure-score-assets"
	results_json=get_query(api_keys,url,querystring)
	return results_json

def list_workbenches_vulnerabilities(api_keys,querystring):
	url = "https://cloud.tenable.com/workbenches/vulnerabilities"
	results_json=get_query(api_keys,url,querystring)
	return results_json

def get_vulnerability_count(api_keys,querystring):
	decoded=list_workbenches_vulnerabilities(api_keys,querystring)
	vuln_count=decoded["total_vulnerability_count"]
	return vuln_count

def get_asset_count(api_keys,payload):
	decoded=search_assets(api_keys,payload)
	asset_count=decoded["pagination"]["total"]
	return asset_count

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

def list_vuln_filters(api_keys,payload):
	url="https://cloud.tenable.com/filters/workbenches/vulnerabilities"
	decoded = post_query(api_keys,url,payload)
	return decoded

def list_asset_filters(api_keys,payload):
	url="https://cloud.tenable.com/filters/workbenches/assets"
	decoded = post_query(api_keys,url,payload)
	return decoded


def list_plugin_outputs(api_keys,plugin_id):
	url = "https://cloud.tenable.com/workbenches/vulnerabilities/"+plugin_id+"/outputs"
	querystring={}
	results_json=get_query(api_keys,url,querystring)
	return results_json

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

def search_findings(api_keys,payload):
	url="https://cloud.tenable.com/api/v3/findings/vulnerabilities/host/search"
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

def create_tag_value(api_keys,payload):
	url="https://cloud.tenable.com/tags/values"
	decoded = post_query(api_keys,url,payload)
	return decoded

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

def vulns_export_status(api_keys,export_uuid):
	url="https://cloud.tenable.com/vulns/export/"+export_uuid+"/status"
	decoded=get_query(api_keys,url,{})
	return decoded

def assets_export_status(api_keys,export_uuid):
	url="https://cloud.tenable.com/assets/export/"+export_uuid+"/status"
	decoded=get_query(api_keys,url,{})
	return decoded

def compliance_export_status(api_keys,export_uuid):
	url="https://cloud.tenable.com/compliance/export/"+export_uuid+"/status"
	decoded=get_query(api_keys,url,{})
	return decoded

def download_vuln_chunk(api_keys,export_uuid,chunk_id):
	url="https://cloud.tenable.com/vulns/export/"+export_uuid+"/chunks/"+chunk_id
	decoded=get_query(api_keys,url,{})
	return decoded

def download_assets_chunk(api_keys,export_uuid,chunk_id):
	url="https://cloud.tenable.com/assets/export/"+export_uuid+"/chunks/"+chunk_id
	decoded=get_query(api_keys,url,{})
	return decoded

def download_compliance_chunk(api_keys,export_uuid,chunk_id):
	url="https://cloud.tenable.com/compliance/export/"+export_uuid+"/chunks/"+chunk_id
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
