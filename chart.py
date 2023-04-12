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

def line_dual_y(df,labels):
	'''
	'''
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

def line(df,labels):
	'''
	'''
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

def bar(df,colors,xlabel_rot,legend_labels):
	'''
	'''
	if len(colors)>0:
		ax=df.plot.bar(legend=True,color=colors,rot=xlabel_rot)
	else:
		ax=df.plot.bar(legend=True,rot=xlabel_rot)
	img_file="image_temp.png"
	f = lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m')
	ax.set_xticklabels([ f(x.get_text()) for x in ax.get_xticklabels()])
	ax.yaxis.grid(True,linestyle="dashed")
	ax.set_axisbelow(True)
	if len(legend_labels)>0:
		ax.legend(legend_labels)
	plt.tight_layout()
	plt.savefig(img_file)
	time.sleep(1)
	data_uri = base64.b64encode(open(img_file, 'rb').read()).decode('utf-8')
	img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
	os.remove(img_file)
	return img_tag

def bar2(df,colors,xlabel_rot,legend_labels):
	'''
	'''
	if len(colors)>0:
		ax=df.plot.bar(legend=True,color=colors,rot=xlabel_rot)
	else:
		ax=df.plot.bar(legend=True,rot=xlabel_rot)
	img_file="image_temp.png"
	f = lambda x: datetime.strptime(x, '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
	ax.set_xticklabels([ f(x.get_text()) for x in ax.get_xticklabels()])
	ax.yaxis.grid(True,linestyle="dashed")
	ax.set_axisbelow(True)
	if len(legend_labels)>0:
		ax.legend(legend_labels)
	plt.tight_layout()
	plt.savefig(img_file)
	time.sleep(1)
	data_uri = base64.b64encode(open(img_file, 'rb').read()).decode('utf-8')
	img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
	os.remove(img_file)
	return img_tag

def box(df,fliers):
	'''
	'''
	ax=df.plot.box(legend=True,showfliers=fliers)
	img_file="image_temp.png"
	ax.yaxis.grid(True,linestyle="dashed")
	ax.set_axisbelow(True)
	plt.savefig(img_file)
	time.sleep(1)
	data_uri = base64.b64encode(open(img_file, 'rb').read()).decode('utf-8')
	img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
	os.remove(img_file)
	return img_tag
