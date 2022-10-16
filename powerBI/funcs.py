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
	print(compliant,not_compliant,totals,sla_eff,ttf_ave)
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
