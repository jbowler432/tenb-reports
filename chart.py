import json
import pandas as pd
import sys
import utilities as ut
from datetime import datetime
from datetime import date
import csv
import base64
import matplotlib.pyplot as plt
import time
import os

'''
Routines for producing charts for html reports.
Images are usually returned as a base64 embedded object
that can be used directly in an img tag. Allows for stand-alone
html document with embedded images.
'''

def line_dual_y(json_data,labels):
	'''
	'''
	df=pd.DataFrame(json_data)
	df=df.set_index('date')
	df.index.name="Date"
	print(df)
	ax=df.iloc[:,0].plot(label=labels[0], legend=True, marker='.')
	ax=df.iloc[:,1].plot(secondary_y=True,label=labels[1],legend=True,marker='.')
	img_file="image_temp.png"
	#f = lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
	#ax.set_xticklabels([ f(x.get_text()) for x in ax.get_xticklabels()])
	plt.savefig(img_file)
	time.sleep(1)
	data_uri = base64.b64encode(open(img_file, 'rb').read()).decode('utf-8')
	img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
	os.remove(img_file)
	return img_tag

def line(json_data,labels):
	'''
	'''
	df=pd.DataFrame(json_data)
	df=df.set_index('date')
	df.index.name="Date"
	print(df)
	ax=df.plot(legend=True)
	img_file="image_temp.png"
	#f = lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
	#ax.set_xticklabels([ f(x.get_text()) for x in ax.get_xticklabels()])
	plt.savefig(img_file)
	time.sleep(1)
	data_uri = base64.b64encode(open(img_file, 'rb').read()).decode('utf-8')
	img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
	os.remove(img_file)
	return img_tag

def bar(json_data,labels):
	'''
	'''
	df=pd.DataFrame(json_data)
	df=df.set_index('date')
	df.index.name="Date"
	print(df)
	ax=df.plot.bar(legend=True)
	img_file="image_temp.png"
	f = lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
	ax.set_xticklabels([ f(x.get_text()) for x in ax.get_xticklabels()])
	plt.tight_layout()
	plt.savefig(img_file)
	time.sleep(1)
	data_uri = base64.b64encode(open(img_file, 'rb').read()).decode('utf-8')
	img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
	os.remove(img_file)
	return img_tag