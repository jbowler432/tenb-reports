import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import utilities as ut
import htmlRoutines as hr
import pandas as pd
import datetime
import time
import json
import chart

'''
This Python script analyses data for fixed vulnerabilities.
'''

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

html_file=reports_dir+"ttfix_stats.html"
json_file=results_dir+"fixed_vulns.json"

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
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,json_file)

# process the saved json files and generate html report
decoded=ut.calculate_fix_times(json_file)
df=pd.DataFrame(decoded)
df=df.set_index('date')
df.index.name="Date"
df2=df[['total','critical','high','medium','low']]
monthly_averages=df2.resample('M').mean()
monthly_counts=df2.resample('M').count()
monthly_medians=df2.resample('M').median()
print(monthly_averages)
print(monthly_counts)
print(monthly_medians)
#sept_df=df.loc['2022-09-01':'2022-09-30']
#sept_averages=sept_df.resample('D').mean()
colors={'total':'#0070b6','critical':'#f63442','high':'#ff9757','medium':'#f9c23b','low':'#7bb147'}
legend_labels=[]
xlabel_rot=0
img_tag=chart.bar(monthly_averages,colors,xlabel_rot,legend_labels)
img_tag2=chart.bar(monthly_counts,colors,xlabel_rot,legend_labels)
img_tag3=chart.box(df2,False)
img_tag4=chart.box(df2,True)
img_tag5=chart.bar(monthly_medians,colors,xlabel_rot,legend_labels)

# generate the html report
body_txt="\n<h1>Remediation Statistics</h1>"
today=datetime.date.today()
report_desc="Shows average remediation times and number of vulnerabilities fixed each month."
report_desc+="\n<br>("+str(today)+")"
body_txt+="<div class=reportdesc>"+report_desc+"</div>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Average Remediation Times</h2>(per vulnerability in days)<br>\n"
body_txt+=img_tag
body_txt+="</div>"
body_txt+="<table width=100%><tr><td>&nbsp;</td></table>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Median Remediation Times</h2>(per vulnerability in days)<br>\n"
body_txt+=img_tag5
body_txt+="</div>"
body_txt+="<table width=100%><tr><td>&nbsp;</td></table>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Number of Vulnerabilities Fixed</h2>\n"
body_txt+=img_tag2
body_txt+="</div>"
body_txt+="<table width=100%><tr><td>&nbsp;</td></table>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Fix Time Spread (no outliers)</h2>\n"
body_txt+=img_tag3
body_txt+="</div>"
body_txt+="<table width=100%><tr><td>&nbsp;</td></table>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Fix Time Spread (with outliers)</h2>\n"
body_txt+=img_tag4
body_txt+="</div>"


hr.gen_html_report(body_txt,html_file,styles_dir)
