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
	eff=0
	if totals>0:
		eff=int(100*compliant/totals)
	return compliant,not_compliant,totals,eff

def apply_filter(mitigated,plugin_dct,filters):
	results=[]
	found=0
	for x in mitigated:
		pid=x['pid']
		#print(plugin_dct[pid])
		exploitable=plugin_dct[pid]['exploitable']
		pname=plugin_dct[pid]['pname']
		severity=plugin_dct[pid]['severity']
		if 'exploitable' in filters:
			if exploitable:
				found=1
		if 'pnames' in filters:
			if ut.found_app(pname,filters['pnames']):
				found=1
		if 'severity' in filters:
			if filters['severity']==severity:
				found=1
		if found==1:
			results.append(x)
		found=0
	return results

def add_id(input_lst,sla_id):
	results2=[]
	for y in input_lst:
		temp_dct={}
		temp_dct.update(y)
		temp_dct.update({'sla_id':sla_id})
		#print(temp_dct)
		results2.append(temp_dct)
	return results2

def return_sla_info(rid,inputs):
	sla=inputs['sla']
	filters=inputs['filters']
	rds=inputs['rds']
	pref=inputs['pref']
	desc=inputs['desc']
	sla_id=inputs['sla_id']+"_"+rid
	if len(filters)==0:
		filtered_dataset=rds
	else:
		filtered_dataset=apply_filter(rds,pref,filters)
	df=pd.DataFrame(filtered_dataset)
	#print(df)
	ttf_ave=int(df['ttfix'].mean())
	compliant,not_compliant,totals,sla_eff=calculate_fix_sla(df,sla)
	#print(compliant,not_compliant,totals,sla_eff,ttf_ave)
	sla_dct={
		'sla_id':str(sla_id),
		'rid':str(rid),
		'desc':desc,
		'sla':str(sla),
		'sla_eff':str(sla_eff),
		'ttf_ave':ttf_ave,
		'compliant':str(compliant),
		'not_compliant':str(not_compliant)
	}
	fds=add_id(filtered_dataset,str(sla_id))
	return sla_dct,fds

def process_ifacing(region_id,mitigated_ifacing_raw):
	decoded=ut.read_json_file(mitigated_ifacing_raw)
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
			'ttfix':ttfix,
			'rid':region_id
		}
		results.append(tmp_dct)
	return results

def process_sc_ifacing(region_id,mitigated_ifacing_raw):
	decoded=ut.read_json_file(mitigated_ifacing_raw)
	results=[]
	plugin_dct={}
	for x in decoded['response']['results']:
		#for (k,v) in x.items():
		#	print(k)
		#print(" ")
		#asset_uuid=x['uuid'] #need to check if this is the asset uuid
		ip=x['ip']
		ips=x['ips']
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
		ttfix=ut.date_diff_unix(ffound,lfound)
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
			'lfixed':datetime.datetime.utcfromtimestamp(int(lfound)).strftime('%Y-%m-%d'),
			'ttfix':ttfix,
			'rid':region_id
		}
		results.append(tmp_dct)
	return results
