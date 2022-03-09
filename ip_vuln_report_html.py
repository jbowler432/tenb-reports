import tenbCore as tc

api_keys=tc.read_keys("../io_keys.json","sandbox")
host_ip_range="10.200.0.0/24"
filter={
"filter.0.filter":"host.target",
"filter.0.quality":"eq",
"filter.0.value":host_ip_range,
}
report_type="html"
results_file="../reports/workbench.html"
tc.check_and_download_workbench(api_keys,filter,results_file,report_type)
