import angr 
import sys
path = sys.argv[1]
print (path)
proj = angr.Project(path)
obj = proj.loader.main_object
state = proj.factory.entry_state()
print ("Entry point of main programe is: %s"%hex(obj.entry))
print ("Start mem addr is: %s\nEnd mem addr is: %s "%(hex(obj.min_addr),hex(obj.max_addr)))
print ("Advance Usage: -s <segments> -S <sections> -Es <Entry segment> \n")
print ("To check password backdoor: bkdr \n")
Selection = raw_input()

#Function for cheking backdoor password 
def Pass_test():
    state = proj.factory.entry_state(stdin = angr.SimFile)
    while True:
        succ = state.step()
        if len (succ.successors) == 2:
            break
        state = succ.successors[0]
    state1, state2 = succ.successors
#Inputing this data to retrieve bitvectore representing all read data
    input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)
    print (state1.solver.eval(input_data,cast_to = bytes))
    print (state2.solver.eval(input_data,cast_to = bytes))


if (Selection == "-s"):
	print ("Segments of the file are: %s"%(obj.segments))
	
elif(Selection == "-S"):
    print ("Sections of the file are %s"%(obj.sections))
	
elif (Selection == "-Es"):
    print ("Entry is in segment: %s"%obj.find_segment_containing(obj.entry))
    
elif (Selection == "bkdr"):
    Pass_test()
    
else:
	print ("Please select valid argument")    

 

 

