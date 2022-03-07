import tenbCore as tc
import tenbAbstract as ta
import beautifyResults as br

# extract some compliance data
asset_lst=[]
last_seen="01/09/2021"
ta.asset_compliance_export_json("../io_keys.json","ep",asset_lst,last_seen,"../reports/compliance.json")
br.compliance_result_summary("../reports/compliance.json")

#cidr="0.0.0.0/0"
#ta.cidr_vuln_export_json("../io_keys.json","sandbox",cidr,"../reports/all_vulns.json")
#br.vuln_result_summary("../reports/all_vulns.json")



