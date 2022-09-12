import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import utilities as ut
import htmlRoutines as hr
import pandas as pd
import datetime
import time
import json

'''
This Python script produces some statictics for patching vulnerabilities.
It does the following:
- Downloads all fixed vulnerabilities within the last 90 days using the export API
- Saves the export to file (fixed_vulns) so that you can perform different
  analysis without re-downloading the data every time. Set get_new_data=0
  if you dont want a fresh download
- Parese the raw json file of downloaded results and produces a html report
- Host average are calculate first, then those averages are averaged
- Results are shown using means and medians
- Results are grouped based on severity. Servity groupings are shown for CVSS and VPR
'''

def get_ttf_averages(input_file,use_vpr,use_means):
	decoded=ut.read_json_file(input_file)
	count=0
	results=[]
	for x in decoded:
		ffound=x["first_found"]
		lfound=x["last_found"]
		lfixed=x["last_fixed"]
		ipv4=x["asset"]["ipv4"]
		uuid=x["asset"]["uuid"]
		pid=x["plugin"]["id"]
		severity=x["severity"]
		ttfix=ut.date_diff(ffound,lfixed)
		if use_vpr==1:
			vpr=0
			if "vpr" in x["plugin"]:
				if "score" in x["plugin"]["vpr"]:
					vpr=x["plugin"]["vpr"]["score"]
				#print(vpr)
			if vpr >= 9.0:
				severity="critical"
			elif vpr >= 7.0:
				severity="high"
			elif vpr >= 4.0:
				severity="medium"
			else:
				severity="low"
		result_dct={"severity":severity,"time_to_fix":ttfix,"uuid":uuid}
		results.append(result_dct)
		count+=1
	#print(count)
	myTable=pd.DataFrame(results)
	grouped=myTable.groupby(['uuid','severity'])
	grouped_means=grouped.mean().values
	grouped_medians=grouped.median().values
	counter=0
	means={}
	medians={}
	maxs={}
	ttf_stats=[]
	fout=open("../results/host_time_to_fix.csv",'w+')
	for (uuid,severity), group in grouped:
		if use_means==1:
			ttf_stats.append({"uuid":uuid,"severity":severity,"mean":int(grouped_means[counter][0])})
		else:
			ttf_stats.append({"uuid":uuid,"severity":severity,"mean":int(grouped_medians[counter][0])})
		fout.write(uuid+","+severity+","+str(int(grouped_means[counter][0]))+","+str(int(grouped_medians[counter][0]))+"\n")
		counter+=1
	fout.close()
	stats_table=pd.DataFrame(ttf_stats)
	stats_grouped=stats_table.groupby(['severity'])
	counter=0
	for (severity), group in stats_grouped:
		medians.update({severity:round(stats_grouped.median().values[counter][0])})
		means.update({severity:round(stats_grouped.mean().values[counter][0])})
		maxs.update({severity:stats_grouped.max().values[counter][1]})
		counter+=1
	print(medians)
	return means,medians,maxs

def gen_widget(means,medians,maxs,heading,current_text):
	body_text=current_text
	body_text+="<div class=page_section>"
	body_text+=heading
	body_text+="\n<br><br><table class=table1 width=350px>"
	body_text+="<tr><td>Severity</td><td align=center>Mean</td><td align=center>Median</td><td align=center>Max</td>"
	body_text+="\n<tr><td>Critical</td><td align=center>"+str(means["critical"])+"</td><td align=center>"+str(medians["critical"])+"</td><td align=center>"+str(maxs["critical"])+"</td>"
	body_text+="\n<tr><td>High</td><td align=center>"+str(means["high"])+"</td><td align=center>"+str(medians["high"])+"</td><td align=center>"+str(maxs["high"])+"</td>"
	body_text+="\n<tr><td>Medium</td><td align=center>"+str(means["medium"])+"</td><td align=center>"+str(medians["medium"])+"</td><td align=center>"+str(maxs["medium"])+"</td>"
	body_text+="\n<tr><td>Low</td><td align=center>"+str(means["low"])+"</td><td align=center>"+str(medians["low"])+"</td><td align=center>"+str(maxs["low"])+"</td>"
	body_text+="</table>"
	body_text+="</div>"
	return body_text

'''
Main Program
'''
# file and directory locations
key_file="../../io_keys.json" # location of your key file
#sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"
output_file=reports_dir+"patching_cadence.html"

fixed_vulns=results_dir+"fixed_vulns.json"

#sc_keys=sc.read_SC_keys(sc_key_file)
api_keys=tc.read_keys(key_file,"sandbox")

get_new_data = 0

if get_new_data==1:
	# export fixed data for last 90 days
	unixtime=ut.unix_time(90)
	num_assets=1000
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,fixed_vulns)

# process the saved json files and generate html report
use_vpr=0
use_means=1
means,medians,maxs=get_ttf_averages(fixed_vulns,use_vpr,use_means)
body_text="<h1>Patch Cadence Report</h1>"
report_desc="This report shows statistics for patching times calculated "
report_desc+="by exporting the vuln database and calculating the difference "
report_desc+="between the last_fixed and first_seen dates. Statistics are "
report_desc+="calculated at the host level first then averaged across all hosts. "
report_desc+="Different views are provided to show the differences between using "
report_desc+="medians and means, both at a host and system wide level. Different "
report_desc+="aggregations are also shown depending on whether severity categories "
report_desc+="are aligned to CVSS or VPR."
body_text+="<div class=reportdesc>"+report_desc+"</div>"
heading="\n<h2>Stats for Host Means</h2>(severity = cvss)"
return_text=gen_widget(means,medians,maxs,heading,body_text)

use_vpr=0
use_means=0
means,medians,maxs=get_ttf_averages(fixed_vulns,use_vpr,use_means)
heading="\n<h2>Stats for Host Medians</h2>(severity = cvss)"
body_text=gen_widget(means,medians,maxs,heading,return_text)

#force new line
body_text+="<table width=100%><tr><td>&nbsp;</td></table>"

use_vpr=1
use_means=1
means,medians,maxs=get_ttf_averages(fixed_vulns,use_vpr,use_means)
heading="\n<h2>Stats for Host Means</h2>(severity = vpr)"
return_text=gen_widget(means,medians,maxs,heading,body_text)

use_vpr=1
use_means=0
means,medians,maxs=get_ttf_averages(fixed_vulns,use_vpr,use_means)
heading="\n<h2>Stats for Host Medians</h2>(severity = vpr)"
body_text=gen_widget(means,medians,maxs,heading,return_text)


hr.gen_html_report(body_text,output_file,styles_dir)
