import json
import pandas as pd
import numpy as np

def read_json_file(input_file):
    with open(input_file,'r') as openfile:
        decoded=json.load(openfile)
    return decoded

def dict_subset(dict,keys):
	new_dict={k: dict[k] for k in keys}
	return new_dict

def compliance_result_summary(input_file):
	decoded=read_json_file("../reports/compliance.json")
	#print(decoded)
	results=[]
	for x in decoded:
		data_subset=dict_subset(x,('asset_uuid','audit_file','status','check_name'))
		results.append(data_subset)
		#print(data_subset)
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['asset_uuid','audit_file','status'])
	print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	for (asset,audit,status), group in grouped:
		print(str(counter),asset,audit,status,grouped_counts[counter][0])
		counter+=1

def vuln_result_summary(input_file):
	decoded=read_json_file("../reports/all_vulns.json")
	#print(decoded)
	results=[]
	for x in decoded:
		#data_subset=dict_subset(x,('asset_uuid','audit_file','status','check_name'))
		results.append({'hostname':x['asset']['hostname'],'plugin':x['plugin']['description'],'severity':x['severity']})
		#print(data_subset)
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['hostname','severity'])
	print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	for (hostname,severity), group in grouped:
		print(str(counter),hostname,severity,grouped_counts[counter][0])
		counter+=1
