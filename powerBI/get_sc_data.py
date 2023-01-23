import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbSCcore as sc
import htmlRoutines as hr
import reportTemplates as rt
import pandas as pd
import utilities as ut
import datetime
import json
import funcs as fc
import normalise_sc_vuln_data as nvd
import normalise_sc_asset_data as nad
import normalise_sc_mitigated_data as nmd
import e8slas as e8
import sev_slas as ss

sc_key_file="../../sc_keys.json"
sc_keys=sc.read_SC_keys(sc_key_file)
region_id='2'
# tags for Internet facing systems
tag_cat_ifacing="Essential8"
tag_val_ifacing="Internet-Facing"
asset_list_ifacing="Internet-Facing"


# file and directory locations
raw_dir="raw/" # the directory for your results
vulns_dir="vulns/"
mitigated_dir="mitigated/"
e8slas_dir="e8slas/"
e8mitigated_dir="e8mitigated/"
sev_slas_dir="sev_slas/"
sev_mitigated_dir="sev_mitigated/"
# raw downloaded data from APIs
vulns_raw_fname=raw_dir+"vulns_"+region_id+".json"
assets_raw_fname=raw_dir+"assets_"+region_id+".json"
mitigated_raw_fname=raw_dir+"mitigated_"+region_id+".json"
mitigated_ifacing_raw_fname=raw_dir+"mitigated_ifacing_"+region_id+".json"
# converted data using raw files as the input
vulns_converted_fname=vulns_dir+"vulns_"+region_id+".json"
vulns_plugins_fname="vulns_plugins.json"
assets_converted_fname="assets.json"
mitigated_converted_fname=mitigated_dir+"mitigated_"+region_id+".json"
mitigated_plugins_fname="mitigated_plugins.json"
e8sla_summary_fname=e8slas_dir+"e8slas_"+region_id+".json"
e8sla_detailed_fname=e8mitigated_dir+"e8mitigated_"+region_id+".json"
sla_summary_fname=sev_slas_dir+"slas_"+region_id+".json"
sla_detailed_fname=sev_mitigated_dir+"mitigated_"+region_id+".json"

'''
Main Program Loop
'''

get_asset_data=1
get_vuln_data=1
get_fix_data=1
get_ifacing_data=1

time_period=180

'''
Download the raw data
'''

if get_vuln_data==1: # raw vuln data
	vuln_tool="vulndetails"
	query={
		"type" : "vuln",
		"tool" : vuln_tool,
		'filters': [
			{'filterName': 'lastSeen', 'operator': '=', 'value': '0:'+str(time_period)},
			{'filterName': 'severity', 'operator': '=',
			'value': [{'id': '1', 'name': 'Low', 'description': 'Low Severity'},
			{'id': '2', 'name': 'Medium', 'description': 'Medium Severity'},
			{'id': '3', 'name': 'High', 'description': 'High Severity'},
			{'id': '4', 'name': 'Critical', 'description': 'Critical Severity'}]}
		]
	}
	sc_server,port,token,cookies=sc.get_token(sc_keys)
	decoded=sc.get_vulns("cumulative",query,sc_server,port,token,cookies,vulns_raw_fname)
	sc.close_session(sc_server,port,token,cookies)

if get_asset_data==1: # Raw Asset Data
	sc_server,port,token,cookies=sc.get_token(sc_keys)
	decoded=sc.call_sc_hosts(sc_server,port,token,cookies)
	#print(decoded)
	with open(assets_raw_fname,'w') as outfile:
		json.dump(decoded,outfile)

if get_fix_data==1: # raw vuln data
	vuln_tool="vulndetails"
	query={
		"type" : "vuln",
		"tool" : vuln_tool,
		'filters': [
			{'filterName': 'lastSeen', 'operator': '=', 'value': '0:'+str(time_period)},
			{'filterName': 'severity', 'operator': '=',
			'value': [{'id': '1', 'name': 'Low', 'description': 'Low Severity'},
			{'id': '2', 'name': 'Medium', 'description': 'Medium Severity'},
			{'id': '3', 'name': 'High', 'description': 'High Severity'},
			{'id': '4', 'name': 'Critical', 'description': 'Critical Severity'}]}
		]
	}
	sc_server,port,token,cookies=sc.get_token(sc_keys)
	decoded=sc.get_vulns("patched",query,sc_server,port,token,cookies,mitigated_raw_fname)
	sc.close_session(sc_server,port,token,cookies)

if get_ifacing_data==1: # raw vuln data
	vuln_tool="vulndetails"
	query={
		"type" : "vuln",
		"tool" : vuln_tool,
		'filters': [
			{'filterName': 'lastSeen', 'operator': '=', 'value': '0:'+str(time_period)},
			{'filterName': 'severity', 'operator': '=', 'value': [{'id': '1', 'name': 'Low', 'description': 'Low Severity'}, {'id': '2', 'name': 'Medium', 'description': 'Medium Severity'}, {'id': '3', 'name': 'High', 'description': 'High Severity'}, {'id': '4', 'name': 'Critical', 'description': 'Critical Severity'}]},
			{'filterName': 'asset', 'operator': '=', 'value': {'id': '116', 'name': 'Internet-Facing', 'description': '', 'uuid': 'D906A47E-14E9-4171-BBEB-2DA37963CD90'}}
		]
	}
	sc_server,port,token,cookies=sc.get_token(sc_keys)
	decoded=sc.get_vulns("patched",query,sc_server,port,token,cookies,mitigated_ifacing_raw_fname)
	sc.close_session(sc_server,port,token,cookies)

'''
#Process the raw data
'''
nvd.process_vuln_data(region_id,vulns_raw_fname,vulns_converted_fname,vulns_plugins_fname)
nad.process_asset_data(region_id,assets_raw_fname,assets_converted_fname)
mitigated_results,mitigated_plugins_results=nmd.process_fix_data(region_id,mitigated_raw_fname,mitigated_converted_fname,mitigated_plugins_fname)
mitigated_ifacing_results=fc.process_sc_ifacing(region_id,mitigated_ifacing_raw_fname)

'''
Calculate some Essential 8 SLAs
'''
e8slas={
	"exploitable":2,
	"common_apps":14,
	"operating_systems":14,
	"internet_facing":14
}
e8.calc_e8slas(e8slas,region_id,mitigated_results,mitigated_plugins_results,mitigated_ifacing_results,e8sla_summary_fname,e8sla_detailed_fname)

'''
#Calculate some severity based SLAs
'''
slas={
	"critical":14,
	"high":30,
	"medium":30,
	"low":30
}
ss.calc_slas(slas,region_id,mitigated_results,mitigated_plugins_results,sla_summary_fname,sla_detailed_fname)
