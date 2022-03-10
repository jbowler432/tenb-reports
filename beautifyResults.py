import json
import pandas as pd
import sys

def read_json_file(input_file):
    with open(input_file,'r') as openfile:
        decoded=json.load(openfile)
    return decoded

def dict_subset(dict,keys):
	new_dict={k: dict[k] for k in keys}
	return new_dict


def get_hostname(uuid,input_file):
    decoded=read_json_file(input_file)
    #print(decoded)
    hostname=""
    for x in decoded:
        if x['id']==uuid:
            hostname=str(x['hostnames'][0])+" - "+str(x['ipv4s'][0])
    return hostname



def compliance_result_summary(input_file,output_file):
	decoded=read_json_file(input_file)
	#print(decoded)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
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
		counter+=1
	table_str="<div class=page_section>\n<table class=table1 width=100%>"
	table_str+="<tr><td width=500px>Hostname</td><td width=500px>Audit Type</td><td width=80px align=center>Failed</td><td width=80px align=center>Passed</td><td width=80px align=center>Warning</td>"
	for (k,v) in asset_dct.items():
		hostname=get_hostname(k,"../results/assets.json")
		table_str+="<tr><td>"+hostname+"</td>\n"
		table_str+="<td>"+v['audit']+"</td><td class=critical>"+str(v['failed'])+"</td><td class=low>"+str(v['passed'])+"</td><td class=high>"+str(v['warning'])+"</td>"
		#for (j,p) in v.items():
		#	table_str+="<td>"+str(j)+"</td><td>"+str(p)+"</td>"
	table_str=table_str+"</table></div>"
	gen_html_report(table_str,output_file)


def assets_result_summary(input_file,output_file):
    decoded=read_json_file(input_file)
    if len(decoded) ==0:
        sys.exit("\nThe export query returned no data")
    #print(decoded)
    results=[]
    for x in decoded:
        data_subset=dict_subset(x,('id','last_seen','ipv4s','hostnames','fqdns','tags'))
        results.append(data_subset)
    myTable=pd.DataFrame(results)
    print(myTable)
    #grouped=myTable.groupby(['hostname','severity'])
    #print(grouped.count())
    #grouped_counts=grouped.count().values
    #print(grouped_counts)



def vuln_result_summary(input_file,output_file):
	decoded=read_json_file(input_file)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
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
	# gen html  report
	table_str="<div class=page_section>\n<table class=table1 width=90%>"
	table_str+="<tr><td width=500px>Host</td><td width=80px align=center>Critical</td><td width=80px align=center>High</td><td width=80px align=center>Medium</td><td width=80px align=center>Low</td><td width=80px align=center>Info</td>"
	for (k,v) in host_dct.items():
		table_str+="<tr><td>"+k+"</td>\n"
		for (j,p) in v.items():
			table_str+="<td class="+str(j)+">"+str(p)+"</td>"
	table_str=table_str+"</table></div>"
	gen_html_report(table_str,output_file)


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
	# read in javascrip file for producing graphs
	#f.write('<script>\n')
	#
	#f2=open("Chart.min.js","r")
	#for line in f2:
	#	f.write(line)
	#f2.close()
	#f.write('</script>\n')
	f.write('</head>\n<body>\n')
