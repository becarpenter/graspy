"""Experimental ASA Loader. Definitely not production code.
This is just for proof of concept. See module graspi.py
for copyright and licence info.

An ASA handled by the loader must call
   graspi.checkrun(asa_handle, asa_name)
regularly in its main loop. If the function
returns False, the ASA must gracefully close down
all operations and sub-threads and then exit.

The ASA loader regularly checks the file 'asafs.txt'
and (re)loads any modules listed in the file that are
not already running. Each module will be a separate
Python thread. The check is repeated after one minute.

If an ASA module exits (gracefully or by an exception)
it will be reloaded (after up to one minute).

If a module name in the file is preceded by "-",
the ASA will be signalled to stop via checkrun()
and unloaded (after up to one minute).

A line in the file starting with "#" is a comment.
"""
import graspi
import threading
import importlib
import time
import traceback

class _asa_instance:
    """Internal use only"""
    def __init__(self, fname, thrid, running):
        self.fname = fname      #the ASA's file name
        self.thread_id = thrid  #which thread?
        self.run = running      #running?
        self.handle = None      #the ASA's handle
        self.name = ""          #the ASA's name
        self.mod = False        #was loaded previously?
                                #(if so, stores Python module id)
        self.stop = False       #stop requested
        

def _rf(f):
    """Return a file as a list of strings"""
    file = open(f, "r",encoding='utf-8', errors='replace')
    l = file.readlines()
    file.close()
    return l

def checkrun(asa_handle, asa_name):
    """To be called in its main loop by every ASA.
Returns True normally, False if the ASA must exit ASAP.
"""
    global _loaded
    #check validity valid by a dummy call
    err,_ = graspi.get_flood(asa_handle, _dummy)
    if err == graspi.errors.noASA:
        graspi.ttprint("Checked: invalid handle")
        return False

    #handle known?
    _llock.acquire()
    #graspi.tprint("Incheck got lock")
    for a in _loaded:
        if a.handle == asa_handle:
            #known, process it
            if not a.stop:
                _llock.release()
                graspi.ttprint("Checked: OK:", asa_name)
                return True
            else:
                _llock.release()
                graspi.tprint("Stopping", asa_name)
                return False
    #handle is unknown
    thrid = threading.get_ident()
    for a in _loaded:
        if a.thread_id == thrid:
            #found it
            a.handle = asa_handle
            a.name = asa_name
            _llock.release()
            graspi.ttprint("Checked: added:", asa_name)
            return True
    _llock.release()
    graspi.tprint("Checked: cannot find entry for", asa_handle, asa_name)    
    return False

graspi.checkrun = checkrun   #add to GRASP API


class _new_ASA(threading.Thread):
    """Internal use only"""
####################################################
#
####################################################
    def __init__(self, asaf):
        threading.Thread.__init__(self, daemon=True)
        self.asaf = asaf
        
    def run(self):
        global _loaded
        asaf = self.asaf
        load_state = _never_loaded
        mod = False
        expunge = False
        _llock.acquire()
        for a in _loaded:
            if a.fname == asaf:
                if not a.mod:
                    load_state = _is_loaded
                    a.state = load_state
                    _llock.release()
                    graspi.tprint(asaf, "is running")
                    break
                else:
                    if not a.thread_id:
                        load_state = _was_loaded
                        a.state = load_state
                        mod = a.mod
                        a.handle = None
                        a.name = ""
                        a.thread_id = threading.get_ident()
                        a.run = True
                        a.stop = False
                        _llock.release()
                        graspi.tprint(asaf, "was previously loaded")
                        break
                    else:
                        load_state = _running
                        a.state = load_state
                        _llock.release()
                        graspi.tprint(asaf, "is running again")
                        break
                    
        if load_state == _never_loaded:
            _loaded.append(_asa_instance(asaf, threading.get_ident(), True))
            _llock.release()
            graspi.tprint("Importing", asaf)
            try:
                mod = importlib.import_module(asaf)
                graspi.tprint(asaf, "terminated")
            except Exception as ex:
                if  type(ex).__name__== 'ModuleNotFoundError':
                    graspi.tprint("Cannot find", asaf)
                    expunge = True
                else:
                    graspi.tprint("Exception in", asaf, ":", ex)
                    traceback.print_exc() #so we can diagnose

        if load_state == _was_loaded:            
            graspi.tprint("Re-importing", asaf)
            try:
                importlib.reload(mod)
                graspi.tprint(asaf, "terminated")
            except Exception as ex:
                graspi.tprint("Exception in", asaf, ":", ex)
                traceback.print_exc()  #so we can diagnose

        if load_state == _never_loaded or load_state == _was_loaded:
            #need to ensure asa is deregistered and mark it in the
            #loaded list as exited
            _llock.acquire()
            for a in _loaded:
                if a.fname == asaf:
                    if expunge:
                        _loaded.remove(a)
                    elif a.handle:
                        #need to deregister ASA (in case...)
                        graspi.tprint("Removing", a.name)
                        err = graspi.deregister_asa (a.handle, a.name)
                        if err and err != graspi.errors.noASA:
                            graspi.tprint("Loader deregistration error",
                                          graspi.etext[err])
                    a.stop = False
                    a.mod = mod
                    a.thread_id = None
                    a.run = False
            _llock.release()

#set up globals
            
_never_loaded = 0
_is_loaded = 1
_was_loaded = 2
_running = 3
_dummy = graspi.objective("dummy")

#initialise list of loaded ASAs
_loaded = []  #list of _asa_instance
_llock = threading.Lock()

def main():
    global _loaded

    #no user dialogue
    graspi.skip_dialogue(testing=False, selfing=True, diagnosing=True,
                         quadsing=True, be_dull=False)
    #start GRASP with the loader as a pseudo-ASA
    err, asa_handle = graspi.register_asa("ASA_loader")
    graspi.grasp._multi_asas = True
    ####That's to bypass the _i_sent_it hack and the session ID clash
    graspi.init_bubble_text("ASA Loader")
    graspi.tprint("ASA Loader started")

    while True:
        #read in file of ASA module file names
        asafl = _rf("asafs.txt")
        for m in asafl:
            if m[0] == "#":
                continue
            if len(m) > 1:
                m = m[:-1]
                if m[0] == "-":
                    #stop this ASA
                    m = m[1:]
                    saystop = False
                    _llock.acquire()
                    for a in _loaded:
                        if a.fname == m:
                            a.stop = True
                            saystop = True
                            break
                    _llock.release()
                    if saystop:
                        graspi.tprint("Stopping", m)                        
                else:
                    graspi.tprint("Trying", m)
                    _new_ASA(m).start()
                    time.sleep(5)    #pause between starting ASAs
        live = []
        _llock.acquire()
        for a in _loaded:
            if a.run:
                live.append(a.fname)
        _llock.release()
        graspi.tprint(len(live), "active ASAs:", live)           
            
            
        time.sleep(60)       #recheck file every minute

main()
    



