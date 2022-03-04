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
	print(decoded)
'''
	results=[]
	for x in decoded:
		asset_uuid=x["asset_uuid"]
		audit_file=x["audit_file"]
		status=x["status"]
		check_name=x["check_name"]
		data_subset=dict_subset(x,('asset_uuid','audit_file','status'))
		results.append(data_subset)
		#print(data_subset)
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['asset_uuid','audit_file','status'])
	print(grouped.agg(np.size))
'''
