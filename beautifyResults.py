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
	#print(myTable)
	grouped=myTable.groupby(['asset_uuid','audit_file','status'])
	#print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	new_uuid=""
	old_uuid=""
	asset_dct={}
	for (asset,audit,status), group in grouped:
		new_uuid=asset
		if new_uuid!=old_uuid:
			asset_dct.update({asset:{'audit':audit,'failed':0,'passed':0,'warning':0,'error':0}})
			asset_dct[asset].update({status.lower():grouped_counts[counter][0]})
		else:
			asset_dct[asset].update({status.lower():grouped_counts[counter][0]})
		old_uuid=asset
		#print(str(counter),asset,audit,status,grouped_counts[counter][0])
		counter+=1
	for (k,v) in asset_dct.items():
		print(k,"\n",v,"\n")

def vuln_result_summary(input_file):
	decoded=read_json_file("../reports/all_vulns.json")
	#print(decoded)
	results=[]
	for x in decoded:
		#data_subset=dict_subset(x,('asset_uuid','audit_file','status','check_name'))
		results.append({'hostname':x['asset']['hostname'],'plugin':x['plugin']['description'],'severity':x['severity']})
		#print(data_subset)
	myTable=pd.DataFrame(results)
	#print(myTable)
	grouped=myTable.groupby(['hostname','severity'])
	#print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	host_old=""
	host_new=""
	host_dct={}
	for (hostname,severity), group in grouped:
		host_new=hostname
		if host_new != host_old:
			host_dct.update({hostname:{'critical':0,'high':0,'medium':0,'low':0,'info':0}})
			host_dct[hostname].update({severity:grouped_counts[counter][0]})
		else:
			host_dct[hostname].update({severity:grouped_counts[counter][0]})
		#print(str(counter),hostname,severity,grouped_counts[counter][0])
		counter+=1
		host_old=hostname
	for (k,v) in host_dct.items():
		print(k,' - ',v)
	table_str=dct_to_table(host_dct)
	gen_html_report(table_str,"../reports/test.html")

def dct_to_table(dct):
	table_str="<table>"
	for (k,v) in dct.items():
		table_str=table_str+"<tr><td>"+k+str(v)+"</td>"
	table_str=table_str+"</table>"
	return table_str

def gen_html_report(body,output_file):
	fin=open('html_header.txt','r')
	file_text=fin.read()
	fin.close
	fout=open(output_file,'w+')
	fout.write(file_text)
	fout.write("\n<body>")
	fout.write('<div id="reportContent">\n')
	fout.write(body)
	fout.write('</div></html>')
	fout.close()
