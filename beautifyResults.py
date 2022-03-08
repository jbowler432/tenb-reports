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
	# gen html  report
	table_str="<div class=bar_chart_fl>\n<table class=table1 width=90%>"
	table_str+="<tr><td width=500px>Host</td><td width=80px align=center>Critical</td><td width=80px align=center>High</td><td width=80px align=center>Medium</td><td width=80px align=center>Low</td><td width=80px align=center>Info</td>"
	for (k,v) in host_dct.items():
		table_str+="<tr><td>"+k+"</td>\n"
		for (j,p) in v.items():
			table_str+="<td class="+str(j)+">"+str(p)+"</td>"
	table_str=table_str+"</table></div>"
	gen_html_report(table_str,"../reports/test.html")


def gen_html_report(body,output_file):
	fout=open(output_file,'w+')
	write_html_header(fout)
	fout.write(body)
	fout.write('</html>')
	fout.close()

def write_html_header(f):
	html_header='<html>\n'\
		'<head>\n'\
		'<title>Tenable Report</title>\n'\
		'<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />\n'\
		'<meta http-equiv="Pragma" content="no-cache" /><meta http-equiv="Expires" content="0" />\n'
	f.write(html_header)
	#
	# readin style sheet
	f2=open("style.css","r")
	for line in f2:
		f.write(line)
	f2.close()
	f.write('<script>\n')
	#
	# read in javascrip file for producing graphs
	f2=open("Chart.min.js","r")
	for line in f2:
		f.write(line)
	f2.close()
	f.write('</script>\n')
	#f2=open(input_dir+"insert_javascript.txt","r")
	#for line in f2:
	#	f.write(line)
	#f2.close()
	f.write('</head>\n<body>\n')

