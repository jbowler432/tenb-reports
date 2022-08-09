import json
import pandas as pd
import sys
import utilities as ut
from datetime import datetime
from datetime import date
import csv

'''
Routines for producing html reports
'''

def gen_html_report(body_text,output_file,style_dir):
	fout=open(output_file,'w+')
	write_html_header(fout,style_dir)
	fout.write(body_text)
	fout.write('</html>')
	fout.close()

def write_html_header(f,style_dir):
	html_header='<html>\n'\
		'<head>\n'\
		'<title>Tenable Report</title>\n'\
		'<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />\n'\
		'<meta http-equiv="Pragma" content="no-cache" /><meta http-equiv="Expires" content="0" />\n'
	f.write(html_header)
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

def software_bom(input_file,html_file,style_dir,csv_file):
	'''
	This function is processing json output from SC.
	'''
	decoded=ut.read_json_file(input_file)
	today=date.today()
	table_str="\n<h1>Software BOM</h1>"
	report_desc="This report shows the installed software per host. "
	report_desc+="It looks at the plugin output for plugins 22869 (SSH), 20811 (Windows), 83991 (OSX)."
	report_desc+="Click on the rows to show the software."
	report_desc+="\n<br><br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n"
	table_str+="<table class=table1>\n"
	table_str+="<tr><td>Host Name</td><td align=center>IP Address</td><td>Operating System</td><td>Plugin ID</td><td>Installed Software Count</td>"
	fout=open(csv_file,"w")
	writer=csv.writer(fout)
	id=1
	for results in decoded:
		os=str(results["os"])
		hostname=results["hostname"]
		output=results["output"]
		ipv4=results["ipv4"]
		pluginID=str(results["pluginID"])
		pluginOutput=clean_plugin_output(output)
		lines=pluginOutput.split("\n")
		for x in lines:
			writer.writerow([hostname,ipv4,os,pluginID,x.replace("\t","").strip()])
		#table_str+="\n<tr><td valign=top>"+hostname+"</td><td valign=top>"+ipv4+"</td><td valign=top>"+pluginID+"</td><td>"+clean_string(pluginOutput.strip())+"</td>"
		table_str+='\n<tr onclick="toggle(\''+str(id)+'\')" onmouseover="this.style.cursor=\'pointer\'"><td valign=top>'+hostname+"</td><td valign=top>"+ipv4+"</td><td valign=top>"+os+"</td><td valign=top>"+pluginID+"</td><td>"+str(len(pluginOutput.strip().split("\n")))+"</td>"
		table_str+='\n<tr id="'+str(id)+'" style="display:none;"><td>'+clean_string(pluginOutput.strip())+"</td>"
		id+=1
		#for (k,v) in results.items():
		#	print(k)
		#print(results["dnsName"],results["ips"],results["uuid"],results["pluginID"])
	gen_html_report(table_str,html_file,style_dir)
	fout.close()

def clean_plugin_output(input):
	lines=input.split("\n")
	output=""
	exclude_list=[" ","","The following software are installed on the remote host :","</plugin_output>"]
	#exclude_list.append("Here is the list of packages installed on the remote CentOS Linux system : ")
	#print(exclude_list)
	for line in lines:
		#print(line)
		if line not in exclude_list:
			if "Here is the list of packages" not in line:
				if "#" not in line:
					if "<plugin_output>" not in line:
						output+=line+"\n"
	return output


def assets_subnet_summary(input_file,output_file,style_dir):
	'''
	Produces a html report showing asset counts per /24 subnet.
	Expected input is a json file from /assets/export API.
	Use check_and_download_assets_chunks(api_keys,payload,asset_file) function
	to generate the json file.
	See subnet_report_licensed.py and subnet_report_unlicensed.py for examples.
	'''
	decoded=ut.read_json_file(input_file)
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
			#print(x['ipv4s'])
			ipv4=x['ipv4s'][0]
			ipv4_parts=ipv4.split(".")
			subnet=ipv4_parts[0]+"."+ipv4_parts[1]+"."+ipv4_parts[2]
		if len(x['hostnames']) > 0:
			hostname=x['hostnames'][0]
		if len(x['operating_systems']) > 0:
			operating_system=x['operating_systems'][0]
		#data_subset=dict_subset(x,('id','ipv4s','hostnames','operating_systems'))
		#results.append(data_subset)
		if len(x['ipv4s']) > 0:
			results.append({'ipv4':ipv4,'subnet':subnet,'hostname':hostname,'operating_system':operating_system})
	myTable=pd.DataFrame(results)
	#print(myTable)
	grouped=myTable.groupby(['subnet'])
	#print(grouped.count())
	grouped_counts=grouped.count().values
	#print(grouped_counts)
	counter=0
	asset_count=0
	today=date.today()
	table_str="\n<h1>Class C Summary - Asset Count</h1>"
	report_desc="This report shows the asset count per /24 subnet. Counts equal to 256 "
	report_desc+="May indicate that a network appliance is responding instead of the actual "
	report_desc+="endpoint."
	report_desc+="\n<br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n"
	table_str+="<table class=table1 width=350px>\n"
	table_str+="<tr><td>Subnet</td><td align=center>Asset Count</td>"
	for (subnet), group in grouped:
		print(subnet,grouped_counts[counter][0])
		asset_count+=grouped_counts[counter][0]
		table_str+="<tr><td>"+str(subnet)+".0/24</td><td align=center>"+str(grouped_counts[counter][0])+"</td>"
		counter+=1
	print(asset_count)
	table_str+="<tr><td align=right>Total</td><td align=center>"+str(asset_count)+"</td>"
	gen_html_report(table_str,output_file,style_dir)

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
	decoded=ut.read_json_file(input_file)
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
	'''
	Generates a html report showing a summary of all audit scan findings.
	Needs both asset and compliance json input files generated from the
	/compliance/export and /assets/export api. Files can be downloaded using
	check_and_download_compliance_chunks(api_keys,payload,compliance_file)
	check_and_download_assets_chunks(api_keys,payload,asset_file)
	See compliance_audit_report.py for an example
	'''
	decoded=ut.read_json_file(input_file)
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
	today=date.today()
	table_str="\n<h1>Audit Findings Summary</h1>"
	report_desc="This report shows a summary of the audit findings per host scan."
	report_desc+="\n<br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n<table class=table1 width=100%>"
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
	'''
	Generates a html report showing a summary of all audit scan findings.
	The summary findings can be expanded by clicking on each record to show the fulle details.
	Needs both asset and compliance json input files generated from the
	/compliance/export and /assets/export api. Files can be downloaded using
	check_and_download_compliance_chunks(api_keys,payload,compliance_file)
	check_and_download_assets_chunks(api_keys,payload,asset_file)
	See compliance_audit_report.py for an example
	'''
	decoded=ut.read_json_file(input_file)
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
	today=date.today()
	table_str="\n<h1>Audit Findings</h1>"
	report_desc="This report shows the detailed audit findings per host scan. Click on each record to see the audit details."
	report_desc+="\n<br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n<table>"
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
	'''
	Generates a html report showing all discovered operating systems
	and the asset counts per OS. Uses a json input file from the /assets/export API.
	The required file can be downloaded using.
	check_and_download_assets_chunks(api_keys,payload,asset_file)
	See os_report.py for an example
	'''
	decoded=ut.read_json_file(input_file)
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
	today=date.today()
	table_str="\n<h1>Operating System Summary</h1>"
	report_desc="This report shows all discovered operating systems."
	report_desc+="\n<br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n"
	table_str+="<table class=table1 width=800px>\n"
	for (operating_system), group in grouped:
		print(operating_system,grouped_counts[counter][0])
		asset_count+=grouped_counts[counter][0]
		table_str+="<tr><td>"+str(operating_system)+"</td><td>"+str(grouped_counts[counter][0])+"</td>"
		counter+=1
	print(asset_count)
	table_str+="<tr><td align=right>Total</td><td>"+str(asset_count)+"</td>"
	gen_html_report(table_str,output_file,style_dir)


def show_installed_software(input_file,output_file,style_dir):
	decoded=ut.read_json_file(input_file)
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

def vuln_report_by_plugin(input_dct,output_file,style_dir):
	'''
	Generates a html report showing a summary of vuln findings per plugin.
	See produce_list_of_exploitable_vulns.py for an example
	'''
	today=date.today()
	table_str="\n<h1>Vulnerability by Plugin Report</h1>"
	report_desc="This report shows the vulnerability count per plugin."
	report_desc+="\n<br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n<table class=table1>"
	table_str+="<tr><td width=50px>PluginID</td><td width=150px>Name</td><td>Synopsis</td><td align=center>Count</td><td>Severity</td>"
	for k,v in input_dct.items():
		pid=k
		pname=v["pname"]
		psynopsis=v["psynopsis"]
		count=v["count"]
		severity=v["severity"]
		pdesc=v["pdesc"]
		psolution=v["psolution"]
		assets=ut.list_to_string(v["assets"])
		table_str+="\n<tr><td><b>"+str(pid)+"</b></td>"
		#table_str+='\n<tr onclick="toggle(\''+str(pid)+'\')" onmouseover="this.style.cursor=\'pointer\'"><td>'+str(pid)+"</td>"
		table_str+="<td>"+pname+"</td><td>"+psynopsis+"</td><td align=center>"+str(count)+"</td><td class="+severity+">"+severity+"</td>"
		#table_str+='<tr id="'+str(pid)+'" style="display:none;"><td>'+clean_string(pdesc)+'</td>\n'
		table_str+="\n<tr><td>&nbsp;</td><td valign=top>"+clean_string(pdesc)+"</td>"
		table_str+="<td colspan=3 valign=top>"+psolution+"<br><br>Impacted Assets<br>"+assets+"</td>"
		#table_str+="\n<tr><td>&nbsp;</td><td align=right>Impacted Assets</td><td colspan=3>"+assets+"</td>"
	table_str=table_str+"</table></div>"
	gen_html_report(table_str,output_file,style_dir)


def vuln_result_summary(input_file,output_file,style_dir):
	'''
	Generates a html report showing a summary of vuln findings per host.
	Expects an json input file generated from the /vulns/export API. The
	required file can be generated using
	check_and_download_vuln_chunks(api_keys,payload,results_file)
	See export_vuln_data_html.py for an example
	'''
	decoded=ut.read_json_file(input_file)
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
	today=date.today()
	table_str="\n<h1>Vulnerability Summary Report</h1>"
	report_desc="This report shows the vulnerability count per host."
	report_desc+="\n<br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n<table class=table1 width=90%>"
	table_str+="<tr><td width=500px>Host</td><td>IP Address</td><td width=80px align=center>Critical</td><td width=80px align=center>High</td><td width=80px align=center>Medium</td><td width=80px align=center>Low</td><td width=80px align=center>Info</td>"
	for (k,v) in host_dct.items():
		table_str+="\n<tr><td>"+k+"</td>\n"
		for (j,p) in v.items():
			table_str+="<td class="+str(j)+">"+str(p)+"</td>"
	table_str=table_str+"</table></div>"
	gen_html_report(table_str,output_file,style_dir)

def vuln_result_detailed(input_file,output_file,style_dir):
	'''
	Generates a html report showing a summary of vuln findings per host.
	Full vuln details can be viewed by clicking on each host record.
	Expects an json input file generated from the /vulns/export API. The
	required file can be generated using
	check_and_download_vuln_chunks(api_keys,payload,results_file)
	See export_vuln_data_html.py for an example
	'''
	today=date.today()
	decoded=ut.read_json_file(input_file)
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
	table_str="\n<h1>Vulnerability Detailed Report</h1>"
	report_desc="This report shows the vulnerability count per host. Click on each host to view "
	report_desc+="the vulnerability details."
	report_desc+="\n<br>("+str(today)+")"
	table_str+="<div class=reportdesc>"+report_desc+"</div>"
	table_str+="<div class=page_section>\n<table>"
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
	return_str=return_str.replace("\t","")
	return return_str
