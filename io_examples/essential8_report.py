import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import utilities as ut
import htmlRoutines as hr
import pandas as pd
import reportTemplates as rt
import datetime
import time
import json
import chart

# file and directory locations
key_file="../../io_keys.json" # location of your key file
#sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"
html_file=reports_dir+"essential8_report.html"

json_file=results_dir+"mitigated.json"
json_file_ifacing=results_dir+"mitigated_ifacing.json"

#sc_keys=sc.read_SC_keys(sc_key_file)

get_new_data = 0
api_keys=tc.read_keys(key_file,"sandbox")
tag_cat_ifacing="Essential8"
tag_val_ifacing="Internet-Facing"

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
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,json_file)

	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"tag."+tag_cat_ifacing:[tag_val_ifacing],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,json_file_ifacing)

# process the saved json files and generate html report


body_txt="<h1>Essential 8 Report</h1>"
report_desc="This report shows compliance against ACSC recommendations for patching times."
body_txt+="<div class=reportdesc>"+report_desc+"</div>"

# exploitable vulns - sla = 2 days
filters={
	"exploitable":True
}
sla=2
heading='Exploitable Vulnerabilities'
desc="Shows remediation SLAs and historical remediation times for exploitable vulnerabilities."
desc+=" ACSC recommendations for this class of vulnerabilities is to remediate within 48 hours."
notes=""
body_txt+=rt.sla_widget(sla,json_file,filters,heading,desc,notes)

filters={
	"pnames":['chrome','explorer','office','flash','pdf','excel',' word','java','firefox']
}
sla=14
heading='Commonly Targeted Applications'
desc="Shows remediation SLAs and historical remediation times for commonly targeted applications."
desc+=" This includes applications such asoffice suites, browsers, pdf readers, java and flash."
desc+=" ACSC recommendations for this class of vulnerabilities is to remediate within 2 weeks."
notes="Data in this widget has been filtered by searching for the following strings in plugin names - "+str(filters['pnames'])
body_txt+=rt.sla_widget(sla,json_file,filters,heading,desc,notes)

filters={
	"pnames":['windows xp','windows 7','windows 8','windows 10','windows 11','windows server',
			'windows update',' os ','linux','macos','osx']
}
sla=14
heading='Operating Systems'
desc="Shows remediation SLAs and historical remediation times for operating systems."
desc+=" ACSC recommendations for this class of vulnerabilities is to remediate within 2 weeks."
#desc+="<br><br>Searching for the following strings in plugin names - "+str(filters['pnames'])
notes="Data in this widget has been filtered by searching for the following strings in plugin names - "+str(filters['pnames'])
body_txt+=rt.sla_widget(sla,json_file,filters,heading,desc,notes)

filters={}
sla=14
heading='Internet Facing'
desc="Shows remediation SLAs and historical remediation times for Internet facing systems."
desc+=" ACSC recommendations for this class of vulnerabilities is to remediate within 2 weeks."
notes='Data in this widget has been filtered using the tag "'+tag_cat_ifacing+':'+tag_val_ifacing+'"'
body_txt+=rt.sla_widget(sla,json_file_ifacing,filters,heading,desc,notes)

filters={}
sla=28
heading='Everything'
desc="Shows remediation SLAs and historical remediation times for everything."
desc+=" ACSC recommendations for this class of vulnerabilities is to remediate within 4 weeks."
notes=""
body_txt+=rt.sla_widget(sla,json_file,filters,heading,desc,notes)

hr.gen_html_report(body_txt,html_file,styles_dir)
