import tenbIOcore as tc
import tenbSCcore as sc
import beautifyResults as br
import datetime

# file and directory locations
key_file="../../io_keys.json" # location of your key file
sc_key_file="../sc_keys.json"
results_dir="results/" # the directory for your results
styles_dir="styles/" #style sheet location for web pages


sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)

decoded=sc.get_vulns_by_pluginID(sc_server,port,token,cookies,"10863","cert_info.json")
print(decoded)


sc.close_session(sc_server,port,token,cookies)
