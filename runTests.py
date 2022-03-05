import tenbCore as tc
import tenbAbstract as ta
import beautifyResults as br

'''
# extract some compliance data
#ip_lst=["10.10.1.190"]
#asset_lst=ta.ip_lst_to_asset_lst("../io_keys.json","sandbox",ip_lst)
#asset_lst=["1932a1b3-be7b-45d3-926b-d94599b46ef4"]
#asset_lst=["3fee0e19-1233-4ba7-98be-f44e4affc015"]
'''
asset_lst=[]
ta.asset_compliance_export_json("../io_keys.json","sandbox",asset_lst,"../reports/compliance.json")


# process the compliance resulsts
#api_keys=tc.read_keys("../io_keys.json","sandbox")
#results=tc.get_asset_details(api_keys,"3fee0e19-1233-4ba7-98be-f44e4affc015")
#print(results["hostname"])
br.compliance_result_summary("../reports/compliance.json")

