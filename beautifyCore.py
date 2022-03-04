import json

def read_json_file(input_file):
    with open(input_file,'r') as openfile:
        decoded=json.load(openfile)
    return decoded

def compliance_result_summary(input_file):
    decoded=read_json_file("reports/compliance.json")
    for x in decoded:
        asset_uuid=x["asset_uuid"]
        audit_file=x["audit_file"]
        status=x["status"]
        check_name=x["check_name"]
        print(asset_uuid,audit_file,check_name,status)
