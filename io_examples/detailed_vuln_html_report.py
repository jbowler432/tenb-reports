import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

api_keys=tc.read_keys(key_file,"sandbox")
host_ip_range="192.168.15.0/24"
filter={
"filter.0.filter":"host.target",
"filter.0.quality":"eq",
"filter.0.value":host_ip_range,
}
report_type="html"
results_file=reports_dir+"detailed_vuln_report.html"
tc.check_and_download_workbench(api_keys,filter,results_file,report_type)
