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

def extract_assetids(input_file):
	with open(input_file,'r') as openfile:
		decoded=json.load(openfile)
	asset_lst=[]
	for x in decoded:
		asset={"id":x["id"]}
		asset_lst.append(asset)
	#print(asset_lst)
	return asset_lst


def get_hostname(uuid,input_file):
	decoded=read_json_file(input_file)
	#print(decoded)
	hostname=""
	ipv4=""
	last_seen=""
	for x in decoded:
		if x['id']==uuid:
			hostname=str(x['hostnames'][0])
			ipv4_lst=x['ipv4s']
			last_seen=x['last_seen']
			for x in ipv4_lst:
				ipv4+=x + ' '
	return hostname,ipv4,last_seen

def compliance_result_summary(assets_file,input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	#print(decoded)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	results=[]
	for x in decoded:
		if 'audit_file' in x:
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
	table_str+="<tr><td width=500px>Hostname</td><td>IP Address</td><td>Last Seen</td><td width=500px>Audit Type</td><td width=80px align=center>Failed</td><td width=80px align=center>Passed</td><td width=80px align=center>Warning</td>"
	for (k,v) in asset_dct.items():
		hostname,ipv4,last_seen=get_hostname(k,assets_file)
		last_seen=last_seen.split("T")[0]
		if hostname=="":
			hostname=k
		table_str+="<tr><td>"+hostname+"</td><td>"+ipv4+"</td><td>"+last_seen+"</td>\n"
		table_str+="<td>"+v['audit']+"</td><td class=critical>"+str(v['failed'])+"</td><td class=low>"+str(v['passed'])+"</td><td class=high>"+str(v['warning'])+"</td>"
		#for (j,p) in v.items():
		#	table_str+="<td>"+str(j)+"</td><td>"+str(p)+"</td>"
	table_str=table_str+"</table></div>"
	gen_html_report(table_str,output_file,style_dir)

def compliance_result_detailed(assets_file,input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	#print(decoded)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	results=[]
	for x in decoded:
		if 'audit_file' in x:
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
	table_str="<div class=page_section>\n<table>"
	table_str+="<tr><td width=500px>Hostname</td><td width=120px>IP Address</td><td width=500px>Audit Type</td><td width=80px align=center>Failed</td><td width=80px align=center>Passed</td><td width=80px align=center>Warning</td>"
	table_str+="</table>"
	for (k,v) in asset_dct.items():
		hostname,ipv4,last_seen=get_hostname(k,assets_file)
		last_seen=last_seen.split("T")[0]
		if hostname=="":
			hostname=k
		table_str+='<table><tr onclick="toggle(\''+k+'\')" onmouseover="this.style.cursor=\'pointer\'"><td width=500px>'+hostname+"</td><td width=120px>"+ipv4+"</td>\n"
		table_str+="<td width=500px>"+v['audit']+"</td><td class=critical width=80px>"+str(v['failed'])+"</td><td class=low width=80px>"+str(v['passed'])+"</td><td class=high width=80px>"+str(v['warning'])+"</td>"
		table_str+="</table>"
		table_str+='<table><tr id="'+k+'" style="display:none;"><td>\n'
		table_str+=get_compliance_details(results,k)
		table_str+='</td></table>'
		#for (j,p) in v.items():
		#	table_str+="<td>"+str(j)+"</td><td>"+str(p)+"</td>"
	table_str=table_str+"</div>"
	gen_html_report(table_str,output_file,style_dir)

def get_compliance_details(results,k):
	return_str="<table class=plugdesc>"
	newlist=sorted(results, key=lambda d: d['status'])
	for x in newlist:
		status=x['status'].lower()
		if x['asset_uuid']==k:
			if x['status']!="ERROR":
				return_str+="<tr><td class="+status+">"+x['status']+"</td><td>"+clean_string(x['check_name'])+"</td>\n"
	return_str+="</table>"
	return return_str

def assets_os_summary(input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	#print(decoded)
	results=[]
	for x in decoded:
		ipv4=""
		hostname=""
		operating_system=""
		if len(x['ipv4s']) > 0:
			ipv4=x['ipv4s'][0]
		if len(x['hostnames']) > 0:
			hostname=x['hostnames'][0]
		if len(x['operating_systems']) > 0:
			operating_system=x['operating_systems'][0]
		#data_subset=dict_subset(x,('id','ipv4s','hostnames','operating_systems'))
		#results.append(data_subset)
		results.append({'ipv4':ipv4,'hostname':hostname,'operating_system':operating_system})
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['operating_system'])
	print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	asset_count=0
	table_str="<div class=page_section>\n"
	table_str+="<table class=table1>\n"
	for (operating_system), group in grouped:
		print(operating_system,grouped_counts[counter][0])
		asset_count+=grouped_counts[counter][0]
		table_str+="<tr><td>"+str(operating_system)+"</td><td>"+str(grouped_counts[counter][0])+"</td>"
		counter+=1
	print(asset_count)
	table_str+="<tr><td align=right>Total</td><td>"+str(asset_count)+"</td>"
	gen_html_report(table_str,output_file,style_dir)

def assets_subnet_summary(input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	#print(decoded)
	results=[]
	for x in decoded:
		ipv4=""
		hostname=""
		operating_system=""
		subnet=""
		if len(x['ipv4s']) > 0:
			ipv4=x['ipv4s'][0]
			ipv4_parts=ipv4.split(".")
			subnet=ipv4_parts[0]+"."+ipv4_parts[1]+"."+ipv4_parts[2]
		if len(x['hostnames']) > 0:
			hostname=x['hostnames'][0]
		if len(x['operating_systems']) > 0:
			operating_system=x['operating_systems'][0]
		#data_subset=dict_subset(x,('id','ipv4s','hostnames','operating_systems'))
		#results.append(data_subset)
		results.append({'ipv4':ipv4,'subnet':subnet,'hostname':hostname,'operating_system':operating_system})
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['subnet'])
	print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	asset_count=0
	table_str="<div class=page_section>\n"
	table_str+="<table class=table1>\n"
	for (subnet), group in grouped:
		print(subnet,grouped_counts[counter][0])
		asset_count+=grouped_counts[counter][0]
		table_str+="<tr><td>"+str(subnet)+"</td><td>"+str(grouped_counts[counter][0])+"</td>"
		counter+=1
	print(asset_count)
	table_str+="<tr><td align=right>Total</td><td>"+str(asset_count)+"</td>"
	gen_html_report(table_str,output_file,style_dir)

def os_by_subnet(input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	#print(decoded)
	results=[]
	for x in decoded:
		ipv4=""
		hostname=""
		operating_system=""
		subnet=""
		if len(x['ipv4s']) > 0:
			ipv4=x['ipv4s'][0]
			ipv4_parts=ipv4.split(".")
			subnet=ipv4_parts[0]+"."+ipv4_parts[1]+"."+ipv4_parts[2]
		if len(x['hostnames']) > 0:
			hostname=x['hostnames'][0]
		if len(x['operating_systems']) > 0:
			operating_system=x['operating_systems'][0]
		#data_subset=dict_subset(x,('id','ipv4s','hostnames','operating_systems'))
		#results.append(data_subset)
		results.append({'ipv4':ipv4,'subnet':subnet,'hostname':hostname,'operating_system':operating_system})
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['subnet','operating_system'])
	print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	asset_count=0
	table_str="<div class=page_section>\n"
	table_str+="<table class=table1>\n"
	for (subnet,operating_system), group in grouped:
		print(subnet,operating_system,grouped_counts[counter][0])
		asset_count+=grouped_counts[counter][0]
		table_str+="<tr><td>"+str(subnet)+"</td><td>"+str(operating_system)+"</td><td>"+str(grouped_counts[counter][0])+"</td>"
		counter+=1
	print(asset_count)
	table_str+="<tr><td align=right>Total</td><td>"+str(asset_count)+"</td>"
	gen_html_report(table_str,output_file,style_dir)


def show_installed_software(input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	#print(decoded)
	results=[]
	for x in decoded:
		#data_subset=dict_subset(x,('asset_uuid','audit_file','status','check_name'))
		results.append({'hostname':x['asset']['hostname'],'ipv4':x['asset']['ipv4'],'plugin_id':x['plugin']['id'],'plugin_name':x['plugin']['name'],'plugin_desc':x['plugin']['description'],'output':x['output']})
		#print(data_subset)
	myTable=pd.DataFrame(results)
	print(myTable)
	table_str="<div class=page_section>\n"
	#table_str="<h1>Installed Software</h1>\n"
	table_str+="<table class=table1>\n"
	for x in results:
		k=x['hostname']
		id=x['plugin_id']
		name=x['plugin_name']
		#table_str+="<tr><td valign=top width=300px>"+x['hostname']+"</td><td valign=top>"+clean_string(x['output'])+"</td>"
		table_str+='\n<tr onclick="toggle(\''+k+'\')" onmouseover="this.style.cursor=\'pointer\'"><td width=600px align=left>'+k+"</td>"
		table_str+="<td>"+str(id)+"</td>\n"
		table_str+="<td>"+name+"</td>\n"
		table_str+='<tr id="'+k+'" style="display:none;"><td>'+clean_string(x['output'])+'</td>\n'
	table_str+="</table></div>"
	gen_html_report(table_str,output_file,style_dir)



def vuln_result_summary(input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	#print(decoded)
	results=[]
	for x in decoded:
		#print(x)
		host=""
		ipv4=""
		description=""
		if 'hostname' in x['asset']:
			host=x['asset']['hostname']
			if 'ipv4' in x['asset']:
				ipv4=x['asset']['ipv4']
			if 'description' in x['plugin']:
				description=x['plugin']['description']
		#data_subset=dict_subset(x,('asset_uuid','audit_file','status','check_name'))
			results.append({'hostname':host,'ipv4':ipv4,'plugin':description,'severity':x['severity']})
		#print(data_subset)
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['hostname','ipv4','severity'])
	print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	host_old=""
	host_new=""
	host_dct={}
	for (hostname,ipv4,severity), group in grouped:
		host_new=hostname
		if host_new != host_old:
			host_dct.update({hostname:{'ipv4':ipv4,'critical':0,'high':0,'medium':0,'low':0,'info':0}})
			host_dct[hostname].update({severity:grouped_counts[counter][0]})
		else:
			host_dct[hostname].update({severity:grouped_counts[counter][0]})
		#print(str(counter),hostname,severity,grouped_counts[counter][0])
		counter+=1
		host_old=hostname
	# gen html  report
	table_str="<div class=page_section>\n<table class=table1 width=90%>"
	table_str+="<tr><td width=500px>Host</td><td>IP Address</td><td width=80px align=center>Critical</td><td width=80px align=center>High</td><td width=80px align=center>Medium</td><td width=80px align=center>Low</td><td width=80px align=center>Info</td>"
	for (k,v) in host_dct.items():
		table_str+="\n<tr><td>"+k+"</td>\n"
		for (j,p) in v.items():
			table_str+="<td class="+str(j)+">"+str(p)+"</td>"
	table_str=table_str+"</table></div>"
	gen_html_report(table_str,output_file,style_dir)

def vuln_result_detailed(input_file,output_file,style_dir):
	decoded=read_json_file(input_file)
	if len(decoded) ==0:
		sys.exit("\nThe export query returned no data")
	#print(decoded)
	results=[]
	for x in decoded:
		host=""
		ipv4=""
		description=""
		if 'hostname' in x['asset']:
			host=x['asset']['hostname']
			if 'ipv4' in x['asset']:
				ipv4=x['asset']['ipv4']
			if 'description' in x['plugin']:
				description=x['plugin']['description']
		#data_subset=dict_subset(x,('asset_uuid','audit_file','status','check_name'))
			results.append({'hostname':host,'ipv4':ipv4,'plugin':description,'id':x['plugin']['id'],'name':x['plugin']['name'],'severity':x['severity']})
		#print(data_subset)
	myTable=pd.DataFrame(results)
	print(myTable)
	grouped=myTable.groupby(['hostname','ipv4','severity'])
	print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	host_old=""
	host_new=""
	host_dct={}
	for (hostname,ipv4,severity), group in grouped:
		host_new=hostname
		if host_new != host_old:
			host_dct.update({hostname:{'ipv4':ipv4,'critical':0,'high':0,'medium':0,'low':0,'info':0}})
			host_dct[hostname].update({severity:grouped_counts[counter][0]})
		else:
			host_dct[hostname].update({severity:grouped_counts[counter][0]})
		#print(str(counter),hostname,severity,grouped_counts[counter][0])
		counter+=1
		host_old=hostname
	# gen html  report
	table_str="<div class=page_section>\n<table>"
	table_str+="<tr><td width=250px>Host</td><td width=120px>IP Address</td><td width=80px class=dummy>Critical</td><td width=80px class=dummy>High</td><td width=80px class=dummy>Medium</td><td width=80px class=dummy>Low</td><td width=80px class=dummy>Info</td>"
	table_str+="</table>"
	for (k,v) in host_dct.items():
		table_str+='\n<table><tr onclick="toggle(\''+k+'\')" onmouseover="this.style.cursor=\'pointer\'"><td width=250px>'+k+"</td>\n"
		table_str+="<td width=120px>"+str(v['ipv4'])+"</td>"
		table_str+="<td width=80px class=critical>"+str(v['critical'])+"</td>"
		table_str+="<td width=80px class=high>"+str(v['high'])+"</td>"
		table_str+="<td width=80px class=medium>"+str(v['medium'])+"</td>"
		table_str+="<td width=80px class=low>"+str(v['low'])+"</td>"
		table_str+="<td width=80px class=info>"+str(v['info'])+"</td>"
		table_str+="</table>"
		table_str+='<table><tr id="'+k+'" style="display:none;"><td>'
		table_str+=get_vuln_details(results,k)
		#table_str+="hello"
		table_str+='</td></table>'
	table_str=table_str+"</div>"
	gen_html_report(table_str,output_file,style_dir)

def get_vuln_details(vuln_lst,hostname):
	return_str="<table>"
	newlist=sorted(vuln_lst, key=lambda d: d['severity'])
	for x in newlist:
		if x['hostname']==hostname:
			if x['severity']!="info":
				return_str+="<tr><td width=120px valign=top align=left class="+x['severity']+">"+x['severity']+"</td><td width=100px valign=top align=center>"+str(x['id'])+"</td><td width=630px valign=top>"+x['name']+"</td>\n"
				return_str+="<tr><td valign=top colspan=3 class=plugdesc>"+clean_string(x['plugin'])+"</td>\n"
	return_str+="</table>"
	return return_str

def clean_string(mystr):
	return_str=mystr.replace("<","&lt;")
	return_str=return_str.replace(">","&gt;")
	return_str=return_str.replace("\n","<br>")
	return return_str

def gen_html_report(body,output_file,style_dir):
	fout=open(output_file,'w+')
	write_html_header(fout,style_dir)
	fout.write(body)
	fout.write('</html>')
	fout.close()

def write_html_header(f,style_dir):
	html_header='<html>\n'\
		'<head>\n'\
		'<title>Tenable Report</title>\n'\
		'<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />\n'\
		'<meta http-equiv="Pragma" content="no-cache" /><meta http-equiv="Expires" content="0" />\n'
	f.write(html_header)
	#
	# readin style sheet
	f2=open(style_dir+"style.css","r")
	for line in f2:
		f.write(line)
	f2.close()
	# readin javascript
	f2=open(style_dir+"collapse.js","r")
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
