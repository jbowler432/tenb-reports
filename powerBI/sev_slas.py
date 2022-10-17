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

def calc_slas(slas,region_id,mitigated_dct,mitigated_plugins_dct,sla_summary_fname,sla_detailed_fname):
	sla_summary=[]

	# critical
	filters={
		"severity":'critical'
	}
	inputs={'sla':slas['critical'],'sla_id':'1','desc':'Critical','filters':filters,'rds':mitigated_dct,'pref':mitigated_plugins_dct}
	sla_dct,fds1=fc.return_sla_info(region_id,inputs)
	sla_summary.append(sla_dct)

	# high
	filters={
		"severity":'high'
	}
	inputs={'sla':slas['high'],'sla_id':'2','desc':'High','filters':filters,'rds':mitigated_dct,'pref':mitigated_plugins_dct}
	sla_dct,fds2=fc.return_sla_info(region_id,inputs)
	sla_summary.append(sla_dct)

	# medium
	filters={
		"severity":'medium'
	}
	inputs={'sla':slas['medium'],'sla_id':'3','desc':'Medium','filters':filters,'rds':mitigated_dct,'pref':mitigated_plugins_dct}
	sla_dct,fds3=fc.return_sla_info(region_id,inputs)
	sla_summary.append(sla_dct)

	# critical
	filters={
		"severity":'low'
	}
	inputs={'sla':slas['low'],'sla_id':'4','desc':'Low','filters':filters,'rds':mitigated_dct,'pref':mitigated_plugins_dct}
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
