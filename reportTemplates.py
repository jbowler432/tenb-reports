import json
import pandas as pd
import sys
import utilities as ut
from datetime import datetime
from datetime import date
import csv
import htmlRoutines as hr

'''
Some common reusable report templates. Usually fed from unmodified
json files from the export APIs.
'''

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
		table_str+="\n<tr><td>&nbsp;</td><td valign=top>"+hr.clean_string(pdesc)+"</td>"
		table_str+="<td colspan=3 valign=top>"+psolution+"<br><br>Impacted Assets<br>"+assets+"</td>"
		#table_str+="\n<tr><td>&nbsp;</td><td align=right>Impacted Assets</td><td colspan=3>"+assets+"</td>"
	table_str=table_str+"</table></div>"
	hr.gen_html_report(table_str,output_file,style_dir)

def vulns_summary(json_file,html_file,styles_dir):
	'''
	Uses the export APIs to download the vulnerabilty database as
	a json file. Reads the downloaded json file to produce to custom
	html reports. One is a summary and the other a detailed report.
	The detailed report can be dynamically expanded to show all the
	vulnerability details.
	'''
	decoded=ut.read_json_file(json_file)
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
	hr.gen_html_report(table_str,html_file,styles_dir)

def vulns_detailed(json_file,html_file,styles_dir):
	'''
	Uses the export APIs to download the vulnerabilty database as
	a json file. Reads the downloaded json file to produce to custom
	html reports. One is a summary and the other a detailed report.
	The detailed report can be dynamically expanded to show all the
	vulnerability details.
	'''
	today=date.today()
	decoded=ut.read_json_file(json_file)
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
	hr.gen_html_report(table_str,html_file,styles_dir)

def get_vuln_details(vuln_lst,hostname):
	return_str="<table>"
	newlist=sorted(vuln_lst, key=lambda d: d['severity'])
	for x in newlist:
		if x['hostname']==hostname:
			if x['severity']!="info":
				return_str+="<tr><td width=120px valign=top align=left class="+x['severity']+">"+x['severity']+"</td><td width=100px valign=top align=center>"+str(x['id'])+"</td><td width=630px valign=top>"+x['name']+"</td>\n"
				return_str+="<tr><td valign=top colspan=3 class=plugdesc>"+hr.clean_string(x['plugin'])+"</td>\n"
	return_str+="</table>"
	return return_str

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
	hr.gen_html_report(table_str,output_file,style_dir)

def software_bom(results_file,html_file,styles_dir):
	decoded=ut.read_json_file(results_file)
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
	id=1
	for results in decoded:
		os=str(results["os"])
		hostname=results["hostname"]
		output=results["output"]
		ipv4=results["ipv4"]
		pluginID=str(results["pluginID"])
		pluginOutput=ut.clean_plugin_output(output)
		lines=pluginOutput.split("\n")
		#table_str+="\n<tr><td valign=top>"+hostname+"</td><td valign=top>"+ipv4+"</td><td valign=top>"+pluginID+"</td><td>"+clean_string(pluginOutput.strip())+"</td>"
		table_str+='\n<tr onclick="toggle(\''+str(id)+'\')" onmouseover="this.style.cursor=\'pointer\'"><td valign=top>'+hostname+"</td><td valign=top>"+ipv4+"</td><td valign=top>"+os+"</td><td valign=top>"+pluginID+"</td><td>"+str(len(pluginOutput.strip().split("\n")))+"</td>"
		table_str+='\n<tr id="'+str(id)+'" style="display:none;"><td>'+hr.clean_string(pluginOutput.strip())+"</td>"
		id+=1
		#for (k,v) in results.items():
		#	print(k)
		#print(results["dnsName"],results["ips"],results["uuid"],results["pluginID"])
	table_str+="</table></div>"
	hr.gen_html_report(table_str,html_file,styles_dir)
