import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import utilities as ut
import datetime
import json

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

get_new_data=0
results_file=results_dir+"software_bom_io.json"
html_file=reports_dir+"software_not_installed.html"

if get_new_data==1:
	# export some vuln data
	num_assets=5000
	#plugin_id=[10180] # Ping the remote host
	#plugin_id=[19506] # Nessus Scan Information
	plugin_id=[22869,20811,83991] # installed software
	filters={"plugin_id":plugin_id}
	include_unlicensed=True
	#filters={}
	payload={
		"filters": filters,
		"num_assets": num_assets,
		"include_unlicensed": include_unlicensed
	}
	api_keys=tc.read_keys(key_file,"sandbox")
	decoded=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)
	software=[]
	for results in decoded:
		os=""
		if len(results["asset"]["operating_system"])>0:
			os=results["asset"]["operating_system"][0]
		software.append({"os":os,"hostname":results["asset"]["hostname"],"ipv4":results["asset"]["ipv4"],"pluginID":results["plugin"]["id"],"output":results["output"]})
	with open(results_file,'w') as outfile:
		json.dump(software,outfile)

search_lst=["python3","Visual C"]

'''
Generate the html report from the downloaded data
'''
decoded=ut.read_json_file(results_file)
today=datetime.date.today()
table_str="\n<h1>Required Software Installed or Missing</h1>"
report_desc="This report using a serach string to look for software installed on computers. "
report_desc+="It looks at the plugin output for plugins 22869 (SSH), 20811 (Windows), 83991 (OSX). "
report_desc+="Two different tables are provided. One showing computers where the software is missing "
report_desc+="and another showing a table where the software was found. "
report_desc+="Click on the rows to show the software lists."
report_desc+="\n<br><br>("+str(today)+")"
table_str+="<div class=reportdesc>"+report_desc+"</div>"
id=1
installed=[]
missing=[]
found_counter={}
for x in search_lst:
	found_counter.update({x:0})
for results in decoded:
	os=str(results["os"])
	hostname=results["hostname"]
	output=results["output"]
	ipv4=results["ipv4"]
	pluginID=results["pluginID"]
	found=0
	for x in search_lst:
		if x in output:
			found=1
			current_count=found_counter[x]
			found_counter.update({x:current_count+1})
	if found==1:
		installed.append({"os":os,"hostname":hostname,"output":output,"ipv4":ipv4,"pluginID":pluginID})
for results in decoded:
	if results not in installed:
		missing.append(results)
#print(found_counter)
table_str+="<div class=page_section>\n"
table_str+="Searching for any of the following "+str(search_lst)
for (k,v) in found_counter.items():
	print(k,v)
	table_str+="<br>Found "+str(v)+" instances of "+str(k)
table_str+="<br>Machines missing the required software = "+str(len(missing))
table_str+="</div>"
table_str+="<table width=100%><tr><td>&nbsp;</td></table>"
table_str+="<div class=page_section>\n"
table_str+="<h2>Machines missing the required software</h2>"
table_str+="<table class=table1 width=1000px>\n"
table_str+="<tr><td>Host Name</td><td align=center>IP Address</td><td>Operating System</td><td>Plugin ID</td><td>Installed Software Count</td>"
for results in missing:
	os=str(results["os"])
	hostname=results["hostname"]
	output=results["output"]
	ipv4=results["ipv4"]
	pluginID=str(results["pluginID"])
	pluginOutput=ut.clean_plugin_output(output)
	table_str+='\n<tr onclick="toggle(\''+str(id)+'\')" onmouseover="this.style.cursor=\'pointer\'"><td valign=top>'+hostname+"</td><td valign=top>"+ipv4+"</td><td valign=top>"+os+"</td><td valign=top>"+pluginID+"</td><td>"+str(len(pluginOutput.strip().split("\n")))+"</td>"
	table_str+='\n<tr id="'+str(id)+'" style="display:none;"><td>'+hr.clean_string(pluginOutput.strip())+"</td>"
	id+=1
	#for (k,v) in results.items():
	#	print(k)
	#print(results["dnsName"],results["ips"],results["uuid"],results["pluginID"])
table_str+="</table></div>"
table_str+="<table width=100%><tr><td>&nbsp;</td></table>"
table_str+="<div class=page_section>\n"
table_str+="<h2>Machines with required software installed</h2>"
table_str+="<table class=table1 width=1000px>\n"
table_str+="<tr><td>Host Name</td><td align=center>IP Address</td><td>Operating System</td><td>Plugin ID</td><td>Installed Software Count</td>"
for results in installed:
	os=str(results["os"])
	hostname=results["hostname"]
	output=results["output"]
	ipv4=results["ipv4"]
	pluginID=str(results["pluginID"])
	pluginOutput=ut.clean_plugin_output(output)
	lines=pluginOutput.split("\n")
	table_str+='\n<tr onclick="toggle(\''+str(id)+'\')" onmouseover="this.style.cursor=\'pointer\'"><td valign=top>'+hostname+"</td><td valign=top>"+ipv4+"</td><td valign=top>"+os+"</td><td valign=top>"+pluginID+"</td><td>"+str(len(pluginOutput.strip().split("\n")))+"</td>"
	table_str+='\n<tr id="'+str(id)+'" style="display:none;"><td>'+hr.clean_string(pluginOutput.strip())+"</td>"
	id+=1
	#for (k,v) in results.items():
	#	print(k)
	#print(results["dnsName"],results["ips"],results["uuid"],results["pluginID"])
table_str+="</table>"
table_str+="</div>"
hr.gen_html_report(table_str,html_file,styles_dir)
