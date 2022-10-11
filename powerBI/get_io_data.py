import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import reportTemplates as rt
import pandas as pd
import utilities as ut
import datetime
import json

def calculate_fix_sla(df,sla):
	totals=df.groupby('asset_uuid').apply(lambda df2: sum(df2.ttfix>=0)).sum()
	compliant=df.groupby('asset_uuid').apply(lambda df2: sum(df2.ttfix<=sla)).sum()
	not_compliant=df.groupby('asset_uuid').apply(lambda df2: sum(df2.ttfix>sla)).sum()
	return compliant,not_compliant,totals

def apply_filter(mitigated,plugin_dct,filters):
	results=[]
	found=0
	for x in mitigated:
		pid=x['pid']
		exploitable=plugin_dct[pid]['exploitable']
		pname=plugin_dct[pid]['pname']
		if 'exploitable' in filters:
			if exploitable:
				found=1
		if 'pnames' in filters:
			if ut.found_app(pname,filters['pnames']):
				found=1
		if found==1:
			results.append(x)
		found=0
	return results

def add_id(input_lst,myid):
	results2=[]
	for y in input_lst:
		temp_dct={}
		temp_dct.update(y)
		temp_dct.update({'id':myid})
		#print(temp_dct)
		results2.append(temp_dct)
	return results2


# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

vulns_file=results_dir+"vulns.json"
assets_file=results_dir+"assets.json"
mitigated_file=results_dir+"mitigated.json"
mitigated_ifacing_file=results_dir+"mitigated_ifacing.json"

get_asset_data=0
get_vuln_data=0
get_fix_data=0
get_ifacing_data=0

tag_cat_ifacing="Essential8"
tag_val_ifacing="Internet-Facing"

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

if get_ifacing_data==1:
	# export fixed data for last 90 days
	unixtime=ut.unix_time(90)
	num_assets=250
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"tag."+tag_cat_ifacing:[tag_val_ifacing],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,mitigated_ifacing_file)


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

mitigated_all=results

# process some mitigated Internet Facing data
decoded=ut.read_json_file(mitigated_ifacing_file)
results=[]
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
	results.append(tmp_dct)

mitigated_ifacing=results


# calculate some SLAs
sla_summary=[]

# Everything
df=pd.DataFrame(mitigated_all)
sla=28
compliant,not_compliant,totals=calculate_fix_sla(df,sla)
print(compliant,not_compliant,totals)
sla_dct={
	'id':'0',
	'desc':'Everything',
	'sla':str(sla),
	'compliant':str(compliant),
	'not_compliant':str(not_compliant),
	'totals':str(totals)
}
sla_summary.append(sla_dct)

# Exploitable Vulns
filters={
	"exploitable":True
}
mitigated_exploitable=apply_filter(mitigated_all,plugin_dct,filters)
df=pd.DataFrame(mitigated_exploitable)
sla=2
compliant,not_compliant,totals=calculate_fix_sla(df,sla)
print(compliant,not_compliant,totals)
sla_dct={
	'id':'1',
	'desc':'Exploitable vulnerabilities',
	'sla':str(sla),
	'compliant':str(compliant),
	'not_compliant':str(not_compliant),
	'totals':str(totals)
}
sla_summary.append(sla_dct)

# Commonly Targeted Apps
filters={
	"pnames":['chrome','explorer','office','flash','pdf','excel',' word','java','firefox']
}
mitigated_common_apps=apply_filter(mitigated_all,plugin_dct,filters)
df=pd.DataFrame(mitigated_common_apps)
sla=14
compliant,not_compliant,totals=calculate_fix_sla(df,sla)
print(compliant,not_compliant,totals)
sla_dct={
	'id':'2',
	'desc':'Common Applications',
	'sla':str(sla),
	'compliant':str(compliant),
	'not_compliant':str(not_compliant),
	'totals':str(totals)
}
sla_summary.append(sla_dct)


# Operating Systems
filters={
	"pnames":['windows xp','windows 7','windows 8','windows 10','windows 11','windows server',
			'windows update',' os ','linux','macos','osx']
}
mitigated_operating_systems=apply_filter(mitigated_all,plugin_dct,filters)
df=pd.DataFrame(mitigated_operating_systems)
sla=14
compliant,not_compliant,totals=calculate_fix_sla(df,sla)
print(compliant,not_compliant,totals)
sla_dct={
	'id':'3',
	'desc':'Operating Systems',
	'sla':str(sla),
	'compliant':str(compliant),
	'not_compliant':str(not_compliant),
	'totals':str(totals)
}
sla_summary.append(sla_dct)

# Internet Facing
df=pd.DataFrame(mitigated_ifacing)
sla=14
compliant,not_compliant,totals=calculate_fix_sla(df,sla)
print(compliant,not_compliant,totals)
sla_dct={
	'id':'4',
	'desc':'Internet Facing',
	'sla':str(sla),
	'compliant':str(compliant),
	'not_compliant':str(not_compliant),
	'totals':str(totals)
}
sla_summary.append(sla_dct)

set0=add_id(mitigated_all,'0')
set1=add_id(mitigated_exploitable,'1')
set2=add_id(mitigated_common_apps,'2')
set3=add_id(mitigated_operating_systems,'3')
set4=add_id(mitigated_ifacing,'4')
results_combined=set0+set1+set2+set3+set4


with open("e8_slas.json",'w') as outfile:
	json.dump(sla_summary,outfile)

with open("e8_sla_raw_data.json",'w') as outfile:
	json.dump(results_combined,outfile)

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
