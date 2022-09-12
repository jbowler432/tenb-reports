import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import utilities as ut
import htmlRoutines as hr
import datetime
import time
import json

'''
Given a tag category (tag_cat) this script will cycle through all values
within the tag category and produce a range of statistics including:
- Total Assets
- Licensed Assets
- Percentage of Assets scanned
- Total vuln count
- critical vuln count
- high vuln count
- ces scores
'''

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"
output_file=reports_dir+"statistics_by_tag.html"
results_file=results_dir+"tag_statistics.json"

api_keys=tc.read_keys(key_file,"sandbox")

tag_cat="Networks"

get_new_data=1

if get_new_data==1:
	# get tag values for tag category
	decoded=tc.list_tag_values(api_keys,tag_cat)
	#print(decoded)
	tag_values=[]
	for x in decoded["values"]:
		tag_values.append({"category":x["category_name"],"value":x["value"],"uuid":x["uuid"]})
		print({"category":x["category_name"],"value":x["value"],"uuid":x["uuid"]})

	# get total asset count
	payload = {
		"limit": 100
	}
	total_asset_count=tc.get_asset_count(api_keys,payload)

	# get licensed asset count
	payload = {
		"filter": {"and": [
		{
			"property": "is_licensed",
			"operator": "eq",
			"value": True
		}
		]},
		"limit": 100
	}
	licensed_asset_count=tc.get_asset_count(api_keys,payload)

	#get total vuln count
	querystring={
		"date_range":"30"
	}
	vuln_total=tc.get_vulnerability_count(api_keys,querystring)

	#get critical vuln count
	querystring={
		"date_range":"30",
		"severity": "critical"
	}
	vuln_crit=tc.get_vulnerability_count(api_keys,querystring)

	#get high vuln count
	querystring={
		"date_range":"30",
		"severity": "high"
	}
	vuln_high=tc.get_vulnerability_count(api_keys,querystring)

	results=[]
	result_dct={
		"description": "All Assets",
		"total_asset_count":total_asset_count,
		"licensed_asset_count":licensed_asset_count,
		"vuln_total": vuln_total,
		"vuln_crit" : vuln_crit,
		"vuln_high" : vuln_high
		}
	results.append(result_dct)
	print(result_dct)

	# loop through tag values
	for tag in tag_values:
		time.sleep(2)
		tag_uuid=tag["uuid"]
		tag_cat=tag["category"]
		tag_value=tag["value"]
		key_value=tag_cat+":"+tag_value

		# get total asset count
		payload = {
			"filter": {"and": [
			{
				"property": "tags",
				"operator": "eq",
				"value": [tag_uuid]
			}
			]},
			"limit": 100
		}
		total_asset_count=tc.get_asset_count(api_keys,payload)

		# get licensed asset count
		payload = {
			"filter": {"and": [
			{
				"property": "tags",
				"operator": "eq",
				"value": [tag_uuid]
			},
			{
				"property": "is_licensed",
				"operator": "eq",
				"value": True
			}
			]},
			"limit": 100
		}
		licensed_asset_count=tc.get_asset_count(api_keys,payload)

		#get total vuln count
		querystring={
			"date_range":"30",
			"filter.0.filter": "tag_uuid",
			"filter.0.quality": "eq",
			"filter.0.value": tag_uuid
		}
		vuln_total=tc.get_vulnerability_count(api_keys,querystring)

		#get critical vuln count
		querystring={
			"date_range":"30",
			"severity": "critical",
			"filter.0.filter": "tag_uuid",
			"filter.0.quality": "eq",
			"filter.0.value": tag_uuid
		}
		vuln_crit=tc.get_vulnerability_count(api_keys,querystring)

		#get high vuln count
		querystring={
			"date_range":"30",
			"severity": "high",
			"filter.0.filter": "tag_uuid",
			"filter.0.quality": "eq",
			"filter.0.value": tag_uuid
		}
		vuln_high=tc.get_vulnerability_count(api_keys,querystring)

		result_dct={
			"description": tag_cat + ":" + tag_value,
			"total_asset_count":total_asset_count,
			"licensed_asset_count":licensed_asset_count,
			"vuln_total": vuln_total,
			"vuln_crit" : vuln_crit,
			"vuln_high" : vuln_high
			}
		results.append(result_dct)
		print(result_dct)

	#save results to file
	with open(results_file,'w') as outfile:
		json.dump(results,outfile)

results=ut.read_json_file(results_file)
today=datetime.date.today()

# gen html  report
table_str="\n<h1>Vulnerability Statistics Report</h1>"
report_desc="This report takes a tag category as an input and trawls through every "
report_desc+="tag value to produce a range of vulnerabiity statistics."
table_str+="<div class=reportdesc>"+report_desc+"</div>"
table_str+="<div class=page_section>"
table_str+="<h2>Tag Category : "+tag_cat+"</h2>"
table_str+="\n("+str(today)+")"
table_str+="\n<table class=table1 width=90%>"
table_str+="\n<tr><td>Description</td><td align=center>Total Assets</td>"
table_str+="<td align=center>Licensed Assets</td><td align=center>Asset Scan Percentage</td><td align=center>Total Vulns</td>"
table_str+="<td align=center>Critical</td><td align=center>High</td>"
for x in results:
	print(x)
	assets_scanned=0
	style_color="red"
	if x["total_asset_count"] != 0:
		assets_scanned=100 * x["licensed_asset_count"]/x["total_asset_count"]
	if assets_scanned>84:
		style_color="black"
	table_str+="\n<tr><td width=550>"+x["description"]+"</td>"
	table_str+="<td width=100px align=center>"+str("{:,}".format(x["total_asset_count"]))+"</td>"
	table_str+="<td width=100px align=center>"+str("{:,}".format(x["licensed_asset_count"]))+"</td>"
	table_str+="<td width=100px align=center style='color:"+style_color+";'>"+"{:.1f}".format(assets_scanned)+"</td>"
	table_str+="<td width=100px align=center>"+str("{:,}".format(x["vuln_total"]))+"</td>"
	table_str+="<td class=critical width=100px>"+str("{:,}".format(x["vuln_crit"]))+"</td>"
	table_str+="<td class=high width=100px>"+str("{:,}".format(x["vuln_high"]))+"</td>"
	#table_str+="<td align=center width=80px>"+str(x["ces"])+"</td>"
table_str=table_str+"</table></div>"
hr.gen_html_report(table_str,output_file,styles_dir)
