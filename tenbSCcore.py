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

def call_sc_analysis(sc_server,port,token,cookies,querystring):
	url="https://"+sc_server+":"+port+"/rest/analysis"
	headers={
	'accept': "application/json",
#		'content-type': "application/json",
	'X-SecurityCenter': token
	}
	'''
	querystring={
		"type" : "vuln",
		"query" : { "id" : "7982"},
		"sourceType" : "cumulative",
		"startOffset" : "0",
		"endOffset" : "2"
	}
	querystring={
		"type" : "vuln",
		"query": {
		"type" : "vuln",
		"tool" : "vulndetails",
		"filters" : [{"filterName":"pluginID","operator":"=","value":"10863"}]
		},
		"sourceType" : "cumulative",
		"startOffset" : "0",
		"endOffset" : "2"
	}
	'''
	response=requests.request("POST",url,headers=headers,json=querystring,cookies=cookies,verify=False)
	#print(response.text)
	decoded=json.loads(response.text)
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

def close_session(sc_server,port,token,cookies):
	url="https://"+sc_server+":"+port+"/rest/token"
	headers={
		'accept': "application/json",
		'content-type': "application/json",
		'X-SecurityCenter': token
	}
	response=requests.request("DELETE",url,headers=headers,cookies=cookies,verify=False)
