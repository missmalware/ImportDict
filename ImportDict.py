import pefile
import sys
import csv
import os

#ImportDict.py Version 1
#Created 2015/12/10
#Author: Miss Malware (mm@missmalare.com or @missmalwareblog)

	
#getimports takes pefile, pulls out the imports, and prints the imports that are in the dictionary with their descriptions.
def getimports(dict,binary):
	try:
		pe = pefile.PE(binary)
		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			for imp in entry.imports:
				importname = imp.name
				if importname[-1] == "A":
					importname = importname[:-1]
				elif importname[-1] == "W":
					importname = importname[:-1]
				
				if importname in dict:
					print importname, ": ", dict[importname]
	except WindowsError,IOError:
		print "The system cannot find and/or access the file specified: " + binary
	

#loadict will load a dictionary from a csv file with the import name in column A and the description in column BaseException		
#future versions will support other file types
def loaddict(file):
	try: 
		with open(file, 'rb') as csvfile:
			filereader = csv.reader(csvfile,delimiter=',', quotechar='|')
			dict = {'importName':'description'}
			for row in filereader:
				dict[row[0]] = row[1]
			return dict
	except IOError:
		print "Could not open the dictionary file. Try naming the file dict.csv and putting it in the same directory as ImportDict.py"
		sys.exit()
			

#main function
#arg1 = PE file; arg2 = optional dictionary location 
#if the dictionary location is not provided, program will assume dict.csv is located in the same directory as ImportDict.py

def main():
	if len(sys.argv) == 2: #dictionary path not provided
		dict = loaddict('dict.csv')
	elif len(sys.argv) == 3 and os.path.exists(sys.argv[2]): #dictionary path was provided
		path = os.path.basename(sys.argv[2])
		dict = loaddict(path)
	else:
		print "Please provide the proper inputs. arg1 = PE file; arg2 = optional dictionary location."
		sys.exit()
	
	getimports(dict,sys.argv[1])

if __name__ == "__main__":
    main()