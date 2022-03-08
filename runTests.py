import tenbCore as tc
import tenbAbstract as ta
import beautifyResults as br

# extract some compliance data
#asset_lst=[]
#last_seen="01/07/2021"
#ta.asset_compliance_export_json("../io_keys.json","sandbox",asset_lst,last_seen,"../reports/compliance.json")
#br.compliance_result_summary("../reports/compliance.json")

#cidr="0.0.0.0/0"
#ta.cidr_vuln_export_json("../io_keys.json","sandbox",cidr,"../reports/all_vulns.json")
br.vuln_result_summary("../reports/all_vulns.json")

#ta.ip_vuln_report_html("../io_keys.json","sandbox","10.200.0.0/24","../reports/vulns.html")

