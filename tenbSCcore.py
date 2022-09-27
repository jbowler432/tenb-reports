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
warnings.filterwarnings("ignore")

'''
Functions that interface with the raw REST APIs
'''

def read_SC_keys(keys_file):
    #fileDir = os.path.dirname(os.path.realpath('__file__'))
    #print(fileDir)
    f=open(keys_file,"r")
    keys=json.load(f)
    return keys

def get_token(sc_keys):
	sc_server=sc_keys["server"] # enter you IP here
	uname=sc_keys["user"] # enter your T.sc username here
	pword=sc_keys["password"] # enter your T.sc password here
	port=sc_keys["port"]

	url="https://"+sc_server+":"+port+"/rest/token"
	headers={
		'accept': "application/json",
		'content-type': "application/json"
	}
	querystring={"username":uname,"password":pword}
	mytoken=""
	try:
		response=requests.request("POST",url,headers=headers,params=querystring,verify=False,timeout=3)
		decoded=json.loads(response.text)
		mytoken=str(decoded['response']['token'])
		mycookies=response.cookies
	except:
		print("\nError - could not establish connection to SC")
	return sc_server,port,mytoken,mycookies

def call_sc_scan(sc_server,port,token,cookies):
	url="https://"+sc_server+":"+port+"/rest/scan"
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	response=requests.request("GET",url,headers=headers,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def call_sc_query(sc_server,port,token,cookies):
	url="https://"+sc_server+":"+port+"/rest/query"
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	response=requests.request("GET",url,headers=headers,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def call_sc_asset(sc_server,port,token,cookies):
	url="https://"+sc_server+":"+port+"/rest/asset"
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	response=requests.request("GET",url,headers=headers,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def add_sc_asset_static(sc_server,port,token,cookies,name,definedIPs):
	url="https://"+sc_server+":"+port+"/rest/asset"
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	querystring={
		"type":"static",
		"name":name,
		"definedIPs":definedIPs
	}
	response=requests.request("POST",url,headers=headers,params=querystring,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def patch_sc_asset_static(sc_server,port,token,cookies,id,definedIPs):
	url="https://"+sc_server+":"+port+"/rest/asset/"+id
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	querystring={
		"definedIPs":definedIPs
	}
	response=requests.request("PATCH",url,headers=headers,params=querystring,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def call_sc_asset_id(sc_server,port,token,cookies,id):
	url="https://"+sc_server+":"+port+"/rest/asset/"+id
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	response=requests.request("GET",url,headers=headers,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def call_sc_assetTemplate(sc_server,port,token,cookies):
	url="https://"+sc_server+":"+port+"/rest/assetTemplate"
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	response=requests.request("GET",url,headers=headers,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def call_sc_assetTemplate_id(sc_server,port,token,cookies,id):
	url="https://"+sc_server+":"+port+"/rest/assetTemplate/"+id
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	response=requests.request("GET",url,headers=headers,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def call_sc_analysis(sc_server,port,token,cookies,querystring):
	url="https://"+sc_server+":"+port+"/rest/analysis"
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	response=requests.request("POST",url,headers=headers,json=querystring,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
	return decoded

def get_ip_list(sc_server,port,token,cookies,filters):
	querystring={
		"type" : "vuln",
		"query": {
		"type" : "vuln",
		"tool" : "sumip",
		'filters': filters
		},
		"sourceType" : "cumulative",
		"startOffset" : "0",
		"endOffset" : "0"
	}
	decoded=call_sc_analysis(sc_server,port,token,cookies,querystring)
	endOffset=decoded["response"]["totalRecords"]
	querystring={
		"type" : "vuln",
		"query": {
		"type" : "vuln",
		"tool" : "sumip",
		'filters': filters
		},
		"sourceType" : "cumulative",
		"startOffset" : "0",
		"endOffset" : endOffset
	}
	decoded=call_sc_analysis(sc_server,port,token,cookies,querystring)
	return decoded


def get_vulns_by_pluginID(sc_server,port,token,cookies,pluginID,results_file):
	# we need to call the analysis API twice. First time is
	# to get the number of records so we can use that in the
	# second call as the end offset parameter
	querystring={
		"type" : "vuln",
		"query": {
		"type" : "vuln",
		"tool" : "vulndetails",
		"filters" : [{"filterName":"pluginID","operator":"=","value":pluginID}]
		},
		"sourceType" : "cumulative",
		"startOffset" : "0",
		"endOffset" : "0"
	}
	decoded=call_sc_analysis(sc_server,port,token,cookies,querystring)
	endOffset=decoded["response"]["totalRecords"]
	querystring={
		"type" : "vuln",
		"query": {
		"type" : "vuln",
		"tool" : "vulndetails",
		"filters" : [{"filterName":"pluginID","operator":"=","value":pluginID}]
		},
		"sourceType" : "cumulative",
		"startOffset" : "0",
		"endOffset" : endOffset
	}
	decoded=call_sc_analysis(sc_server,port,token,cookies,querystring)
	with open(results_file,'w') as outfile:
		json.dump(decoded,outfile)
	return decoded

def get_mitigated(sc_server,port,token,cookies,results_file,vuln_tool):
	# we need to call the analysis API twice. First time is
	# to get the number of records so we can use that in the
	# second call as the end offset parameter
	querystring={
		"type" : "vuln",
		"query": {
		"type" : "vuln",
		"tool" : vuln_tool,
		'filters': [{'filterName': 'lastSeen', 'operator': '=', 'value': '0:60'}]
		},
		"sourceType" : "patched",
		"startOffset" : "0",
		"endOffset" : "0"
	}
	decoded=call_sc_analysis(sc_server,port,token,cookies,querystring)
	print(decoded)
	endOffset=decoded["response"]["totalRecords"]
	querystring={
		"type" : "vuln",
		"query": {
		"type" : "vuln",
		"tool" : vuln_tool,
		'filters': [{'filterName': 'lastSeen', 'operator': '=', 'value': '0:60'}]
		},
		"sourceType" : "patched",
		"startOffset" : "0",
		"endOffset" : endOffset
	}
	decoded=call_sc_analysis(sc_server,port,token,cookies,querystring)
	with open(results_file,'w') as outfile:
		json.dump(decoded,outfile)
	return decoded

def close_session(sc_server,port,token,cookies):
	url="https://"+sc_server+":"+port+"/rest/token"
	headers={
		'accept': "application/json",
		'content-type': "application/json",
		'X-SecurityCenter': token
	}
	response=requests.request("DELETE",url,headers=headers,cookies=cookies,verify=False)
