import tenbIOcore as tc
import tenbSCcore as sc
import beautifyResults as br
import datetime
import time
import json

# file and directory locations
key_file="../io_keys.json" # location of your key file
sc_key_file="../sc_keys.json"
results_dir="results/" # the directory for your results
styles_dir="styles/" #style sheet location for web pages
output_file=results_dir+"statistics_by_tag.html"
results_file=results_dir+"tag_statistics.json"

sc_keys=sc.read_SC_keys(sc_key_file)
api_keys=tc.read_keys(key_file,"uni")

'''
# get the ces scores
querystring={}
decoded=tc.exposure_score_assets(api_keys,querystring)
ces_scores={}
for x in decoded["asset_groups"]:
	ces_scores.update({x["name"]:x["exposure_score"]})
print(ces_scores)
with open(results_dir+"ces_scores.json",'w') as outfile:
	json.dump(ces_scores,outfile)


# get tag values for tag category
tag_cat="UQ%20Owner"
decoded=tc.list_tag_values(api_keys,tag_cat)
#print(decoded)
tag_values=[]
for x in decoded["values"]:
	tag_values.append({"category":x["category_name"],"value":x["value"],"uuid":x["uuid"]})

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
ces=ces_scores["Your Organization"]
result_dct={
	"description": "All Assets",
	"total_asset_count":total_asset_count,
	"licensed_asset_count":licensed_asset_count,
	"vuln_total": vuln_total,
	"vuln_crit" : vuln_crit,
	"vuln_high" : vuln_high,
	"ces" : ces
	}
results.append(result_dct)
print(result_dct)

# loop through tag values
for tag in tag_values:
	time.sleep(2)
	#tag_uuid="a7deb637-89bb-42f4-97b8-68419c72af99"
	#tag_cat="UQ Owner"
	#tag_value="Infrastructure and Security"
	tag_uuid=tag["uuid"]
	tag_cat=tag["category"]
	tag_value=tag["value"]
	ces=""
	key_value=tag_cat+":"+tag_value
	if key_value in ces_scores:
		ces=ces_scores[key_value]

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
		"vuln_high" : vuln_high,
		"ces" : ces
		}
	results.append(result_dct)
	print(result_dct)

#save results to file
with open(results_file,'w') as outfile:
	json.dump(results,outfile)
'''
results=br.read_json_file(results_file)

# gen html  report
table_str="<div class=page_section>\n<table class=table1 width=90%>"
table_str+="\n<tr><td>Description</td><td align=center>Total Assets</td>"
table_str+="<td align=center>Licensed Assets</td><td align=center>Total Vulns</td>"
table_str+="<td align=center>Critical</td><td align=center>High</td><td align=center>CES</td>"
for x in results:
	table_str+="\n<tr><td width=550>"+x["description"]+"</td>"
	table_str+="<td width=100px align=center>"+str("{:,}".format(x["total_asset_count"]))+"</td>"
	table_str+="<td width=100px align=center>"+str("{:,}".format(x["licensed_asset_count"]))+"</td>"
	table_str+="<td width=100px align=center>"+str("{:,}".format(x["vuln_total"]))+"</td>"
	table_str+="<td class=critical width=100px>"+str("{:,}".format(x["vuln_crit"]))+"</td>"
	table_str+="<td class=high width=100px>"+str("{:,}".format(x["vuln_high"]))+"</td>"
	table_str+="<td align=center width=80px>"+str(x["ces"])+"</td>"
table_str=table_str+"</table></div>"
br.gen_html_report(table_str,output_file,styles_dir)
