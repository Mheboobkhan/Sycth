import angr 
import sys
path = sys.argv[1]
print (path)
proj = angr.Project(path)
obj = proj.loader.main_object
print ("Entry point of main programe is: %s"%hex(obj.entry))
print ("Start mem addr is: %s\nEnd mem addr is: %s "%(hex(obj.min_addr),hex(obj.max_addr)))

Selection = input(print ("Advance Usage: -s <segments> -S <sections> \n"))

if (Selection == "-s"):
	{
	print ("Segments of the file are: %s"%(obj.segments))
	}
elif(Selection == "-S"):
	{
	print ("Sections of the file are %s"%(obj.sections))
	}
else:
	{
	print ("Please select valid argument")
	}
	
