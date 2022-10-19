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
		pid=str(x['plugin']['id'])
		pname=x['plugin']['name']
		pdesc=x['plugin']['description']
		state=x['state']
		ffound=x['first_found']
		lfound=x['last_found']
		age=ut.date_diff(ffound,lfound)
		current_date=datetime.datetime.now().strftime("%Y-%m-%dT")
		age2=ut.date_diff(ffound,current_date)
		#print(age,age2,ffound,lfound,current_date)
		tmp_dct={
			'asset_uuid':asset_uuid,
			'pid':pid,
			'state':state,
			'ffound':ffound,
			'lfound':lfound,
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
