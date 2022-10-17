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

def calc_e8slas(slas,region_id,mitigated_dct,mitigated_plugins_dct,mitigated_ifacing,sla_summary_fname,sla_detailed_fname):
	sla_summary=[]

	# exploitable vulns
	inputs={'sla':slas['exploitable'],'sla_id':'1','desc':'Exploitable','filters':{"exploitable":True},'rds':mitigated_dct,'pref':mitigated_plugins_dct}
	sla_dct,fds1=fc.return_sla_info(region_id,inputs)
	sla_summary.append(sla_dct)

	# common apps
	filters={
		"pnames":['chrome','explorer','office','flash','pdf','excel',' word','java','firefox']
	}
	inputs={'sla':slas['common_apps'],'sla_id':'2','desc':'Common Apps','filters':filters,'rds':mitigated_dct,'pref':mitigated_plugins_dct}
	sla_dct,fds2=fc.return_sla_info(region_id,inputs)
	sla_summary.append(sla_dct)

	# operating systems
	filters={
		"pnames":['windows xp','windows 7','windows 8','windows 10','windows 11','windows server',
				'windows update',' os ','linux','macos','osx']
	}
	inputs={'sla':slas['operating_systems'],'sla_id':'3','desc':'Operating Systems','filters':filters,'rds':mitigated_dct,'pref':mitigated_plugins_dct}
	sla_dct,fds3=fc.return_sla_info(region_id,inputs)
	sla_summary.append(sla_dct)

	# Internet Facing
	filters={
	}
	inputs={'sla':slas['internet_facing'],'sla_id':'4','desc':'Internet Facing','filters':filters,'rds':mitigated_ifacing,'pref':mitigated_plugins_dct}
	sla_dct,fds4=fc.return_sla_info(region_id,inputs)
	sla_summary.append(sla_dct)
	for x in sla_summary:
		print(x)

	# save the results
	with open(sla_summary_fname,'w') as outfile:
		json.dump(sla_summary,outfile)

	results_combined=fds1+fds2+fds3+fds4
	with open(sla_detailed_fname,'w') as outfile:
		json.dump(results_combined,outfile)
