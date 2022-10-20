import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import reportTemplates as rt
import pandas as pd
import utilities as ut
import datetime
import json
import funcs as fc

def process_vuln_data(region_id,vulns_raw,vulns_converted,vulns_plugins):
	decoded=ut.read_json_file(vulns_raw)
	results=[]
	plugin_dct={}
	for x in decoded['response']['results']:
		#for (k,v) in x.items():
		#	print(k)
		#	#print(x['pluginInfo'])
		#print(" ")
		#asset_uuid=x['uuid'] #need to check if this is the asset uuid
		ip=x['ip']
		ips=x['ips']
		hostUUID=x["hostUUID"]
		uuid=x["uuid"]
		asset_uuid=ip
		#severity_id=x['severity_id']
		severity=x['severity']['name'].lower()
		#print(severity)
		cve=[]
		if 'cve' in x: cve=x['cve']
		#print(cve)
		cvss3=x['cvssV3BaseScore']
		cvss2=x['baseScore'] #need to check
		vpr={}
		if 'vprContext' in x: vpr=x['vprContext']
		#print(vpr)
		vpr_score=''
		if 'vprScore' in x: vpr_score=x['vprScore']
		exploitable=x['exploitAvailable']
		#has_patch=x['plugin']['has_patch']
		pid=str(x['pluginID'])
		pname=x['pluginName']
		pdesc=x['description']
		state=x['hasBeenMitigated']
		ffound=x['firstSeen']
		lfound=x['lastSeen']
		age=ut.date_diff_unix(ffound,lfound)
		current_date=datetime.datetime.now()
		unix_timestamp = int(datetime.datetime.timestamp(current_date))
		age2=ut.date_diff_unix(ffound,unix_timestamp)
		if 'patchPubDate' in x:
			has_patch='True'
		else:
			has_patch='False'
		#print(age2,ffound,unix_timestamp,current_date)
		#if ip=='192.168.16.118':
		#	print(asset_uuid,pid,ip,ips)
		tmp_dct={
			'asset_uuid':asset_uuid,
			'pid':pid,
			'state':state,
			'ffound':datetime.datetime.utcfromtimestamp(int(ffound)).strftime('%Y-%m-%d'),
			'lfound':datetime.datetime.utcfromtimestamp(int(lfound)).strftime('%Y-%m-%d'),
			'age':age2,
			'rid':region_id
		}
		plugin_dct.update({
			pid:{
			'pname':pname,
			'pdesc':pdesc,
			'severity':severity,
			'cve':cve,
			'cvss3':cvss3,
			'cvss2':cvss2,
			#'vpr':vpr,
			'vpr_score':vpr_score,
			'exploitable':exploitable,
			'has_patch':has_patch}
		})
		results.append(tmp_dct)

	with open(vulns_converted,'w') as outfile:
		json.dump(results,outfile)

	try: # see if file already exists
		decoded=ut.read_json_file(vulns_plugins)
		decoded.update(plugin_dct)
		with open(vulns_plugins,'w') as outfile:
			json.dump(decoded,outfile)
	except:
		with open(vulns_plugins,'w') as outfile:
			json.dump(plugin_dct,outfile)
