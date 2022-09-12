import json
import pandas as pd
import sys
import utilities as ut
from datetime import datetime
from datetime import date
import csv

'''
Routines for producing html reports
'''

def gen_html_report(body_text,output_file,style_dir):
	fout=open(output_file,'w+')
	write_html_header(fout,style_dir)
	fout.write(body_text)
	fout.write('</html>')
	fout.close()

def write_html_header(f,style_dir):
	html_header='<html>\n'\
		'<head>\n'\
		'<title>Tenable Report</title>\n'\
		'<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />\n'\
		'<meta http-equiv="Pragma" content="no-cache" /><meta http-equiv="Expires" content="0" />\n'
	f.write(html_header)
	# readin style sheet
	f2=open(style_dir+"style.css","r")
	for line in f2:
		f.write(line)
	f2.close()
	# readin javascript
	f2=open(style_dir+"collapse.js","r")
	for line in f2:
		f.write(line)
	f2.close()
	# read in javascrip file for producing graphs
	#f.write('<script>\n')
	#
	#f2=open("Chart.min.js","r")
	#for line in f2:
	#	f.write(line)
	#f2.close()
	#f.write('</script>\n')
	f.write('</head>\n<body>\n')

def clean_string(mystr):
	return_str=mystr.replace("<","&lt;")
	return_str=return_str.replace(">","&gt;")
	return_str=return_str.replace("\n","<br>")
	return_str=return_str.replace("\t","")
	return return_str
