import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import reportTemplates as rt
import pandas as pd
import utilities as ut
import datetime
import json

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

vulns_file=results_dir+"vulns.json"
assets_file=results_dir+"assets.json"
mitigated_file=results_dir+"mitigated.json"

get_asset_data=0
get_vuln_data=1
get_fix_data=0

api_keys=tc.read_keys(key_file,"sandbox")

if get_asset_data==1:
	# export some asset data
	filters={}
	chunk_size=500
	payload = {
		"filters":filters,
		"chunk_size": chunk_size
	}
	tc.check_and_download_assets_chunks(api_keys,payload,assets_file)

if get_vuln_data==1:
	# export some vuln data
	unixtime=ut.unix_time(90)
	num_assets=200
	filters={
		"severity":["critical","high","medium","low"],
		"last_found":unixtime
	}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,vulns_file)

if get_fix_data==1:
	# export fixed data for last 90 days
	unixtime=ut.unix_time(90)
	num_assets=250
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,mitigated_file)

# process some asset data
decoded=ut.read_json_file(assets_file)
results=[]
for x in decoded:
	#for (k,v) in x.items():
	#	print(k)
	id=x['id']
	agent_uuid=x['agent_uuid']
	network_name=x['network_name']
	ipv4s=x['ipv4s']
	ipv4=''
	if len(ipv4s)>0: ipv4=ipv4s[0]
	hostnames=x['hostnames']
	hostname=''
	if len(hostnames)>0: hostname=hostnames[0]
	operating_systems=x['operating_systems']
	operating_system=''
	if len(operating_systems)>0: operating_system=operating_systems[0]
	acr_score=x['acr_score']
	exposure_score=x['exposure_score']
	tmp_dct={
		'id':id,
		'agent_uuuid':agent_uuid,
		'network_name':network_name,
		'ipv4s':ipv4s,
		'ipv4':ipv4,
		'hostnames':hostnames,
		'hostname':hostname,
		'acr_score':acr_score,
		'exposure_score':exposure_score,
		'operating_systems':operating_systems,
		'operating_system':operating_system
	}
	results.append(tmp_dct)

with open("assets.json",'w') as outfile:
	json.dump(results,outfile)

# process some mitigated data
decoded=ut.read_json_file(mitigated_file)
results=[]
plugin_dct={}
for x in decoded:
	#for (k,v) in x.items():
	#	print(k)
	#print(" ")
	asset_uuid=x['asset']['uuid']
	severity_id=x['severity_id']
	severity=x['severity']
	cve=[]
	if 'cve' in x['plugin']: cve=x['plugin']['cve']
	cvss3=x['plugin']['cvss3_base_score']
	cvss2=x['plugin']['cvss_base_score']
	vpr={}
	if 'vpr' in x['plugin']: vpr=x['plugin']['vpr']
	vpr_score=''
	if 'score' in vpr: vpr_score=vpr['score']
	exploitable=x['plugin']['exploit_available']
	has_patch=x['plugin']['has_patch']
	pid=x['plugin']['id']
	pname=x['plugin']['name']
	pdesc=x['plugin']['description']
	state=x['state']
	ffound=x['first_found']
	lfixed=x['last_fixed']
	ttfix=ut.date_diff(ffound,lfixed)
	tmp_dct={
		'asset_uuid':asset_uuid,
		'pid':pid,
		'state':state,
		'ffound':ffound,
		'lfixed':lfixed,
		'ttfix':ttfix
	}
	plugin_dct.update({
		pid:{
		'pname':pname,
		'pdesc':pdesc,
		'severity':severity,
		'cve':cve,
		'cvss3':cvss3,
		'cvss2':cvss2,
		'vpr':vpr,
		'vpr_score':vpr_score,
		'exploitable':exploitable,
		'has_patch':has_patch}
	})
	results.append(tmp_dct)

with open("mitigated.json",'w') as outfile:
	json.dump(results,outfile)

with open("mitigated_plugins.json",'w') as outfile:
	json.dump(plugin_dct,outfile)


# process some vulnerability data
decoded=ut.read_json_file(vulns_file)
results=[]
plugin_dct={}
for x in decoded:
	#for (k,v) in x.items():
	#	print(k)
	#print(" ")
	asset_uuid=x['asset']['uuid']
	severity_id=x['severity_id']
	severity=x['severity']
	cve=[]
	if 'cve' in x['plugin']: cve=x['plugin']['cve']
	cvss3=x['plugin']['cvss3_base_score']
	cvss2=x['plugin']['cvss_base_score']
	vpr={}
	if 'vpr' in x['plugin']: vpr=x['plugin']['vpr']
	vpr_score=''
	if 'score' in vpr: vpr_score=vpr['score']
	exploitable=x['plugin']['exploit_available']
	has_patch=x['plugin']['has_patch']
	pid=x['plugin']['id']
	pname=x['plugin']['name']
	pdesc=x['plugin']['description']
	state=x['state']
	ffound=x['first_found']
	lfound=x['last_found']
	age=ut.date_diff(ffound,lfound)
	tmp_dct={
		'asset_uuid':asset_uuid,
		'pid':pid,
		'state':state,
		'ffound':ffound,
		'lfound':lfound,
		'age':age
	}
	plugin_dct.update({
		pid:{
		'pname':pname,
		'pdesc':pdesc,
		'severity':severity,
		'cve':cve,
		'cvss3':cvss3,
		'cvss2':cvss2,
		'vpr':vpr,
		'vpr_score':vpr_score,
		'exploitable':exploitable,
		'has_patch':has_patch}
	})
	results.append(tmp_dct)

with open("vulns.json",'w') as outfile:
	json.dump(results,outfile)

with open("vulns_plugins.json",'w') as outfile:
	json.dump(plugin_dct,outfile)