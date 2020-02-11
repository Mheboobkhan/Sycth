import angr 
import sys
import pyfiglet
#from colorama import Fore, Back, Style

# Styling 
ascii_banner = pyfiglet.figlet_format("S c y t h",font="slant")
print (ascii_banner)
ascii_banner1 = pyfiglet.figlet_format("THE WHITEHEART & ALESAWE",font="digital")
print ("By \n"+ascii_banner1)
print ("This is a opensource programe developed by me, anyone can improve it and use it for legal purposes \n\n")
# Need to enter Email here...
path = sys.argv[1]
print ("File Loaded "+path)
proj = angr.Project(path)
obj = proj.loader.main_object # main function address 
shared = proj.loader.shared_objects
state = proj.factory.entry_state() 
print ("===========================================================")
print ("Entry point of main programe is: %s"%hex(obj.entry))
print ("===========================================================")
print ("Start mem addr is: %s\nEnd mem addr is: %s "%(hex(obj.min_addr),hex(obj.max_addr)))
print ("===========================================================")
print ('''Usage:
  seg <segments>
  sec <sections>
  Es <Entry segment>
  bkdr <To check backdoor password>
  dend <To ckeck Deadend inputs>
  shared <Get all shared library for this process>
  info <Checks the security mechanisms>
  offsets <Enter your base offset>
  quit <To quit the program>''')


Selection = raw_input('>> ')



#Function for cheking backdoor password 
def Pass_test():
    # Used to create a file with constrained symbolic content
    state = proj.factory.entry_state(stdin = angr.SimFile) 

    while True:
        succ = state.step()
        if len (succ.successors) == 2 :
            break
        state = succ.successors[0]
        # TO be removed or add in execption handler
        #proj.hook(0x10bbc00, " ", length= 0x4)
        
    state1, state2 = succ.successors
    
#Inputing this data to retrieve bitvectore representing all read data
    input_data = state1.posix.stdin.load(0, state1.posix.stdin.size)
    print (state1.solver.eval(input_data,cast_to = bytes))
    print (state2.solver.eval(input_data,cast_to = bytes))
    
def Sim_mgr ():
    simgr = proj.factory.simgr(state)
    while len (simgr.active) == 1:
        simgr.step()
    simgr.run()
    print (simgr.mp_deadended.posix.dumps(0))



while True:

    if (Selection == "seg"):
    	print ("Segments of the file are: %s"%(obj.segments))

    elif(Selection == "sec"):
        print ("Sections of the file are %s"%(obj.sections))
    	
    elif (Selection == "Es"):
        print ("Entry is in segment: %s"%obj.find_segment_containing(obj.entry))
        
    elif (Selection == "bkdr"):
        Pass_test()
        
    elif (Selection == "dend"):
        Sim_mgr()

    elif (Selection == "shared"):
        print("The shared library for this process %s"%(dict(shared)))

    elif (Selection == "info"):
        print('''Arch Type = {}
Stack Executable = {}
PIC = {}'''.format(proj.arch, obj.execstack, obj.pic))
    # TODO get the offset to the return address from the address that user provides
    elif (Selection == "offsets"):
        print ("Enter your base address")
        base = int(str(input('>> ')), 16)
        retAdd = state.regs.ebp + 0x4
        print(retAdd)
        print(base)
        retOffest = retAdd - base
        print (retOffest)

    elif (Selection == "quit"):
        break
    else:
        print ("Please select valid argument")
    

    Selection = raw_input('>> ')

        
    
