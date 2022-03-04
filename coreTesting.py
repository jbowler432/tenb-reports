import tenbCore as tc
import beautifyCore as bc

api_keys=tc.read_keys("../io_keys.json","sandbox")
results=tc.get_asset_details(api_keys,"3fee0e19-1233-4ba7-98be-f44e4affc015")
print(results["hostname"])
bc.compliance_result_summary("../reports/compliance.json")
