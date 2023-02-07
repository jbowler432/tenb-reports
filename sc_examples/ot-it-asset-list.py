import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbSCcore as sc
import reportTemplates as rt
import json
import requests
import warnings
import csv
import time
warnings.filterwarnings("ignore")

#
# queries tenable.sc using the analysis API. Firstly it pulls a list of informational
# vulnerabilities from a limited plugin set. This is used to generate a unique list of assets.
# In addition to basic asset information like os and ot vendor info, vulnerability severities
# for each asset are pulled using the vuln severity summary api call (one per asset).
#

#
# sub routines
#


def read_keys(keys_file):
    #fileDir = os.path.dirname(os.path.realpath('__file__'))
    #print(fileDir)
    f=open(keys_file,"r")
    keys=json.load(f)
    return keys

def parse_decoded(my_dict):
	for k,v in my_dict.items():
		print(k,"--",v)

def parse_decoded2(my_dict):
	for k,v in my_dict.items():
		print("\n")
		if isinstance(v,dict):
			print(k,"--",v)
			parse_decoded(v)
		else:
			print(k,"--",v)

def save_results_json(my_dict,out_file):
	mylst=[]
	for x in my_dict.items():
		mylst.append(x[1])
	json_dump=json.dumps(mylst)
	f = open(out_file,"w")
	f.write(json_dump)
	f.close()

def save_results(my_dict,output_file):
	with open(output_file, mode='w') as assets_file:
		results_writer = csv.writer(assets_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
		results_writer.writerow(['repo','ip', 'uuid', 'mac', 'name', 'os', 'vendor', 'family', 'firmware', 'type', 'critical', 'high', 'medium', 'low'])
		for x in my_dict.items():
			results_writer.writerow([x[1]["repo_name"],x[1]["ip"],x[1]["uuid"],x[1]["mac"],x[1]["name"],x[1]["os"],x[1]["vendor"],x[1]["family"],x[1]["firmware"],x[1]["type"],x[1]["crit"],x[1]["high"],x[1]["med"],x[1]["low"]])

def get_vuln_summaries(ip,uuid,repo,vulns):
	crit=0
	high=0
	med=0
	low=0
	url="https://"+sc_server+":"+str(port)+"/rest/analysis"
	headers={
		'accept': "application/json",
		'content-type': "application/json",
		'X-SecurityCenter': token
		}
	if uuid=='':
		myquery={"type":"vuln","tool":"sumseverity","filters":[{"filterName":"ip","operator":"=","value":ip},{"filterName":"repositoryIDs","operator":"=","value":repo}]}
	elif ip=='':
		myquery={"type":"vuln","tool":"sumseverity","filters":[{"filterName":"uuid","operator":"=","value":uuid},{"filterName":"repositoryIDs","operator":"=","value":repo}]}
	else:
		myquery={"type":"vuln","tool":"sumseverity","filters":[{"filterName":"ip","operator":"=","value":ip},{"filterName":"uuid","operator":"=","value":uuid},{"filterName":"repositoryIDs","operator":"=","value":repo}]}
	mydata={"type":"vuln","sourceType":"cumulative","query":myquery}
	response=requests.request("POST",url,headers=headers,data=json.dumps(mydata),cookies=cookies,verify=False)
	decoded=json.loads(response.text)
	if decoded['error_msg']=='':
		#print("pulling vuln results for ip = " + str(ip) + ", uuid = " + str(uuid) + ", repo_id = " + str(repo))
		#print("** Vuln Results **")
		#print(decoded["response"]["results"])
		for x in decoded["response"]["results"]:
			if x["severity"]["name"]=="Critical":
				crit=x["count"]
			elif x["severity"]["name"]=="High":
				high=x["count"]
			elif x["severity"]["name"]=="Medium":
				med=x["count"]
			elif x["severity"]["name"]=="Low":
				low=x["count"]
	else:
		print(decoded['error_msg'])
	vulns.update({"crit":crit,"high":high,"med":med,"low":low})

def generate_asset_list(my_dict,asset_info):
	#print(my_dict)
	myresults=my_dict["response"]["results"]
	#print(myresults)
	count=1
	asset_count=0
	#asset_info={}
	asset_key=""
	scada_plugs=["500000","500001","500002","500003","500004","500005","500006","500007","500008","500009","500010","500011","500012","500013","500014","500015","500016","500017","500018","500019","500020"]
	for x in myresults:
		#print("\n")
		#print(x)
		#parse_decoded(x)
		ip=x["ip"]
		uuid=x["uuid"]
		pluginID=x["pluginID"]
		repo=x["repository"]["id"]
		repo_name=x["repository"]["name"]
		asset_key=ip+uuid+repo
		plugins=[]
		plug_text=x["pluginText"]
		# remove <> tags from output
		if len(plug_text.split("<plugin"))>0:
			plug_text=plug_text.split("<plugin_output>")[1]
			plug_text=plug_text.split("</plugin_output>")[0]
		if asset_key in asset_info:
			mac=asset_info[asset_key]["mac"]
			name=asset_info[asset_key]["name"]
			os=asset_info[asset_key]["os"]
			vendor=asset_info[asset_key]["vendor"]
			family=asset_info[asset_key]["family"]
			firmware=asset_info[asset_key]["firmware"]
			type=asset_info[asset_key]["type"]
			crit=asset_info[asset_key]["crit"]
			high=asset_info[asset_key]["high"]
			med=asset_info[asset_key]["med"]
			low=asset_info[asset_key]["low"]
			if pluginID=="19506":
				mac=x["macAddress"]
				name=x["dnsName"]
				os=x["operatingSystem"]
			if pluginID=="54615":
				for line in plug_text.split('\n'):
					if 'Remote device type' in line:
						type=line.split(": ")[1]
			if pluginID in scada_plugs:
				for line in plug_text.split('\n'):
					if 'vendor' in line:
						vendor=line.split(": ")[1]
					elif 'family' in line:
						family=line.split(": ")[1]
					elif 'firmwareVersion' in line:
						firmware=line.split(": ")[1]
					elif 'os:' in line:
						if os=="":
							os=line.split(": ")[1]
					elif 'os :' in line:
						if os=="":
							os=line.split(": ")[1]
					elif 'name:' in line:
						if name=="":
							name=line.split(": ")[1]
					elif 'name :' in line:
						if name=="":
							name=line.split(": ")[1]
					elif 'type:' in line:
						if type=="":
							type=line.split(": ")[1]
					elif 'type :' in line:
						if type=="":
							type=line.split(": ")[1]
			plug_count=asset_info[asset_key]["plug_count"]+1
			#print(asset_info[asset_key]["plugins"])
			tmp_lst=[]
			for i in asset_info[asset_key]["plugins"]:
				tmp_lst.append(i)
			tmp_lst.append(pluginID)
			#plugins=asset_info[asset_key]["plugins"].append(pluginID)
			asset_info.update({asset_key:{"crit":crit,"high":high,"med":med,"low":low,"repo_id":repo,"repo_name":repo_name,"plug_count":plug_count,"plugins":tmp_lst,"ip":ip,"uuid":uuid,"mac":mac,"name":name,"os":os,"vendor":vendor,"family":family,"firmware":firmware,"type":type}})
		else:
			mac=""
			name=""
			os=""
			vendor=""
			family=""
			firmware=""
			type=""
			vulns={"crit":0,"high":0,"med":0,"low":0}
			#get_vuln_summaries(ip,uuid,repo,vulns)
			#print(vulns)
			if pluginID=="19506":
				mac=x["macAddress"]
				name=x["dnsName"]
				os=x["operatingSystem"]
			if pluginID=="54615":
				for line in plug_text.split('\n'):
					if 'Remote device type' in line:
						type=line.split(": ")[1]
			if pluginID in scada_plugs:
				for line in plug_text.split('\n'):
					if 'vendor' in line:
						vendor=line.split(": ")[1]
					elif 'family' in line:
						family=line.split(": ")[1]
					elif 'firmwareVersion' in line:
						firmware=line.split(": ")[1]
					elif 'os:' in line:
						if os=="":
							os=line.split(": ")[1]
					elif 'os :' in line:
						if os=="":
							os=line.split(": ")[1]
					elif 'name:' in line:
						if name=="":
							name=line.split(": ")[1]
					elif 'name :' in line:
						if name=="":
							name=line.split(": ")[1]
					elif 'type:' in line:
						if type=="":
							type=line.split(": ")[1]
					elif 'type :' in line:
						if type=="":
							type=line.split(": ")[1]
			plugins.append(pluginID)
			asset_info.update({asset_key:{"crit":vulns["crit"],"high":vulns["high"],"med":vulns["med"],"low":vulns["low"],"repo_id":repo,"repo_name":repo_name,"plug_count":1,"plugins":plugins,"ip":ip,"uuid":uuid,"mac":mac,"name":name,"os":os,"vendor":vendor,"family":family,"firmware":firmware,"type":type}})
			asset_count=asset_count+1
		#parse_decoded(x)
		count=count+1
	#print(asset_info)
	#parse_decoded2(asset_info)
	print("plugin records processed = "+str(count-1))
	print("asset records processed = "+str(asset_count))
	return asset_count
	#save_results(asset_info)
	#gen_filters(asset_info,filter_lst)


# main program
#
# global vars
#
results_dir="../results/"
reports_dir="../report_samples/"
styles_dir="../styles/"
asset_info={}
csv_file=results_dir+"results.csv"
json_file=results_dir+"results.json"
html_file=reports_dir+"ot_it_assets.html"
vuln_result_limit=10000 # limits the inital set of informational vulnerabilities pulled
pull_vuln_summaries=1
num_assets=0

#
# Establish the session
# login an get the token
# us the token and cookie for future requests
#

sc_key_file="../../sc_keys.json"
sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)

#
# Extract informational plugin data for a range of plugins.
# This enables us to build the asset list with meaningful data
# collected from a variety of plugins
#
url="https://"+sc_server+":"+str(port)+"/rest/analysis"
headers={
	'accept': "application/json",
	'content-type': "application/json",
	'X-SecurityCenter': token
	}
#
# valid tool types
# cceipdetail, cveipdetail, iavmipdetail, iplist, listmailclients, listos, popcount, listservices, listsoftware, listsshservers,
# sumasset, sumcce, sumclassa, sumclassb, sumclassc, sumcve, sumdnsname, sumfamily, sumiavm, sumid, sumip, summsbulletin, sumport,
# sumprotocol, sumremediation, sumseverity, sumuserresponsibility, listvuln, vulndetails, vulnipdetail, vulnipsummary, listwebclients,
# listwebservers, trend
#
# Valid Filters
# acceptedRisk, acceptRiskStatus, assetID, auditFileID, benchmarkName, cceID, cpe, cveID, baseCVSSScore, cvssVector,
# cvssV3BaseScore, cvssV3Vector, dataFormat, daysMitigated, daysToMitigated, dnsName, exploitAvailable, exploitFrameworks, familyID,
# firstSeen, iavmID, ip, lastMitigated, lastSeen, mitigatedStatus, msbulletinID, outputAssets, patchPublished, pluginModified,
# pluginPublished, pluginID, pluginName, pluginText, pluginType, policyID, port, protocol, recastRisk, recastRiskStatus, repositoryIDs,
# responsibleUserIDs, severity, stigSeverity, tcpport, udpport, vulnPublished, wasMitigated, xref, uuid, vprScore
#
#plugins="1,18,11936,19506,54615,500000,500001,500002,500003,500004,500005,500006,500007,500008,500009,500010,500011,500012,500013,500014,500015,500016,500017,500018,500019,500020"
plugins="1,18,11936,19506,54615,500000-599999"
#plugins="1,11936,54615,19506"
myquery={"type":"vuln",
	 "tool":"vulndetails",
	 "startOffset":"0",
	 "endOffset":vuln_result_limit,
	 "filters":[{"filterName":"pluginID","operator":"=","value":plugins}]}
#	 "filters":[{"filterName":"pluginID","operator":"=","value":plugins},{"filterName":"ip","operator":"=","value":"192.168.0.117,192.168.0.100,10.100.102.26"}]}
#	 "filters":[{"filterName":"ip","operator":"=","value":"192.168.0.117,192.168.0.100"}]}
mydata={"type":"vuln",
	"sourceType":"cumulative",
	"query":myquery}
response=requests.request("POST",url,headers=headers,data=json.dumps(mydata),cookies=cookies,verify=False)
decoded=json.loads(response.text)
num_assets=generate_asset_list(decoded,asset_info)
#
if pull_vuln_summaries==1:
	print("About to pull vuln severity summary for "+str(num_assets) + " assets.")
	print("May take some time as its an api call per asset.....")
	count=1
	for k,v in asset_info.items():
		ip=v["ip"]
		uuid=v["uuid"]
		repo=v["repo_id"]
		vulns={}
		newvalues=v
		get_vuln_summaries(ip,uuid,repo,vulns)
		newvalues.update({"crit":vulns["crit"]})
		newvalues.update({"high":vulns["high"]})
		newvalues.update({"med":vulns["med"]})
		newvalues.update({"low":vulns["low"]})
		asset_info.update({k:newvalues})
		print(str(count)+" of "+str(num_assets)+" records. ip="+ip+". Critcals="+str(vulns["crit"])+". Highs="+str(vulns["high"]))
		count=count+1
		#time.sleep(0.05)
#
save_results(asset_info,csv_file)
save_results_json(asset_info,json_file)

#
# close off the session
#
sc.close_session(sc_server,port,token,cookies)


'''
Produce pretty html report
'''
rt.it_ot_asset_report(json_file,html_file,styles_dir)
