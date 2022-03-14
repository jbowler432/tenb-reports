fin = open("tenbCore.py","r")
fout = open("tenbCoreNew.py","w")
for line in fin:
	new_line=line.replace('    ','\t')
	fout.write(new_line)

fin.close()
fout.close()
