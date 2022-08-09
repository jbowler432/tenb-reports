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
results_file=results_dir+"vulns.json"

api_keys=tc.read_keys(key_file,"sandbox")
sc_keys=sc.read_SC_keys(sc_key_file)
