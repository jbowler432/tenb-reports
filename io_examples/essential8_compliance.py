import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import utilities as ut
import beautifyResults as br
import pandas as pd
import datetime
import time
import json

'''
Shows patching compliance against two SLA values
- Exploitable vulns patched within 48 hours
- everything else patched within two weeks
'''

def get_ttf_compliance(input_file):
	decoded=ut.read_json_file(input_file)
	exploitable_fixes=[]
	fixes=[]
	for x in decoded:
		ffound=x["first_found"]
		lfound=x["last_found"]
		lfixed=x["last_fixed"]
		ipv4=x["asset"]["ipv4"]
		uuid=x["asset"]["uuid"]
		pid=x["plugin"]["id"]
		severity=x["severity"]
		exploitable=x["plugin"]["exploit_available"]
		ttfix=ut.date_diff(ffound,lfixed)
		result_dct={"severity":severity,"ttf":ttfix}
		if exploitable==True:
			exploitable_fixes.append(result_dct)
		else:
			fixes.append(result_dct)
	return exploitable_fixes,fixes

def process_df(fix_data,sla):
	myTable=pd.DataFrame(fix_data)
	totals=myTable.groupby('severity').apply(lambda df: sum(df.ttf>=0))
	compliant=myTable.groupby('severity').apply(lambda df: sum(df.ttf<=sla))
	not_compliant=myTable.groupby('severity').apply(lambda df: sum(df.ttf>sla))
	return compliant,not_compliant,totals

def gen_widget(heading,current_text,compliant,not_compliant,totals):
	body_text=current_text
	ccrit=get_val(compliant,"critical")
	chigh=get_val(compliant,"high")
	cmedium=get_val(compliant,"medium")
	clow=get_val(compliant,"low")
	nccrit=get_val(not_compliant,"critical")
	nchigh=get_val(not_compliant,"high")
	ncmedium=get_val(not_compliant,"medium")
	nclow=get_val(not_compliant,"low")
	tcrit=get_val(totals,"critical")
	thigh=get_val(totals,"high")
	tmedium=get_val(totals,"medium")
	tlow=get_val(totals,"low")
	ccrit_per=str(int(100*int(ccrit)/int(tcrit)))
	chigh_per=str(int(100*int(chigh)/int(thigh)))
	cmedium_per=str(int(100*int(cmedium)/int(tmedium)))
	clow_per=str(int(100*int(clow)/int(tlow)))
	body_text+="<div class=page_section>"
	body_text+=heading
	body_text+="\n<br><br><table class=table1 width=450px>"
	body_text+="\n<tr><td>&nbsp;</td><td align=center>Critical</td><td align=center>High</td><td align=center>Medium</td><td align=center>Low</td>"
	body_text+="\n<tr><td>Compliant</td><td align=center>"+ccrit+" ("+ccrit_per+"%)</td>"
	body_text+="<td align=center>"+chigh+" ("+chigh_per+"%)</td>"
	body_text+="<td align=center>"+cmedium+" ("+cmedium_per+"%)</td>"
	body_text+="<td align=center>"+clow+" ("+clow_per+"%)</td>"
	body_text+="\n<tr><td>Not Compliant</td><td align=center>"+nccrit+"</td>"
	body_text+="<td align=center>"+nchigh+"</td>"
	body_text+="<td align=center>"+ncmedium+"</td>"
	body_text+="<td align=center>"+nclow+"</td>"
	body_text+="\n<tr><td>Totals</td><td align=center>"+tcrit+"</td>"
	body_text+="<td align=center>"+thigh+"</td>"
	body_text+="<td align=center>"+tmedium+"</td>"
	body_text+="<td align=center>"+tlow+"</td>"
	body_text+="</table>"
	body_text+="</div>"
	return body_text

def get_val(myseries,key):
	return_val=""
	for i,v in myseries.items():
		if i==key:
			return_val=str(v)
	return return_val


# file and directory locations
key_file="../../io_keys.json" # location of your key file
#sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"
output_file=reports_dir+"essential8_compliance.html"

fixed_vulns=results_dir+"fixed_vulns.json"

#sc_keys=sc.read_SC_keys(sc_key_file)
api_keys=tc.read_keys(key_file,"sandbox")

get_new_data = 0

# download a fresh set of fixed vuln data if required
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
exploitable_fixes,fixes=get_ttf_compliance(fixed_vulns)

compliant,not_compliant,totals=process_df(exploitable_fixes,2)

body_text="<h1>Essential 8 Patching Compliance</h1>"
report_desc="This report shows compliance against ACSC recommendations for patching times."
body_text+="<div class=reportdesc>"+report_desc+"</div>"
heading="\n<h2>Expoitable Vulnerabilities</h2>(patch within 48 hours)"
return_text=gen_widget(heading,body_text,compliant,not_compliant,totals)

compliant,not_compliant,totals=process_df(fixes,14)

heading="\n<h2>Everything Else</h2>(patch within 2 weeks)"
body_text=gen_widget(heading,return_text,compliant,not_compliant,totals)


br.gen_html_report(body_text,output_file,styles_dir)
