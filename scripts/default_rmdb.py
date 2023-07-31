#! /usr/bin/python3

########################################################
# File  : default_rmdb.py
# Author: Ali Abbas Mir 
# Date:   Mar.01.2023
# Note:   Parse the master.yaml and create the __REGRESSION_EXEC_MANAGEMENT_DB 
########################################################

#import fileutil
import yaml
import random
import time
import os
import sys

import inspect

sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+"/templates/python")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+"/scripts/bcr_mods")
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+"/scripts/")
if sys.version_info[0] < 3:
  sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+"/templates/python/python2")

#print("Python searches for the modules in : "+str(sys.path))
## TODO Fixme os.environ["PATH"] += os.pathsep + os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+'/scripts/'
#print("PATH environment variable on your system: "+str(os.environ["PATH"]))
#sys.exit(0)

##!< from dvs_init import *
import uvmf_bcr

try:
  import yaml
  from voluptuous import Required,Optional,Any,In,Schema,MultipleInvalid
  from voluptuous.humanize import humanize_error
  import argparse
  import traceback
  import pprint
  import textwrap
  import logging
  from bcr_mods import *
  import subprocess
  import collections
except ImportError as ie:
  print("ERROR:Missing library: %s" % str(ie))
  print("path: "+str(sys.path))
  sys.exit(1)

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

recursion_check = []
tcdict = {}
builddict = {}
file_read = None
root_dir = None
debug = True
ini = {}
rerun_count = None
mseed = None
testlist_info = []
current_tb = None
logger = logging.getLogger("logger")

def RightNow():
    import datetime
    current_time = datetime.datetime.now().strftime('%H:%M:%S')
    return current_time

# Set up the email parameters
sender_email = "AliAbbasMir@deeproute.ai"
receiver_email = "AliAbbasMir@deeproute.ai"
subject = "Regression started at {}...".format(RightNow())
body = "This is a test email sent from default_rmdb.py"

# Create a multipart message and set the message headers
message = MIMEMultipart()
message["From"] = sender_email
message["To"] = receiver_email
message["Subject"] = subject

# Add body to email
message.attach(MIMEText(body, "plain"))

# Create SMTP session for sending the email
smtp_server = "smtp.partner.outlook.cn"
smtp_port = 587 #587  # use 465 for SSL connections
smtp_username = "aliabbasmir@deeproute.ai"
smtp_password = "****"

#with smtplib.SMTP(smtp_server, smtp_port) as server:
#    server.starttls()  # enable TLS encryption
#    server.login(smtp_username, smtp_password)
#    text = message.as_string()
#    server.sendmail(sender_email, receiver_email, text)

# Returns the actual master seed used to seed the Python random number generator
def returnMasterSeed():
    global mseed
    return mseed

## Variables controllable by user via ini file along with their defaults
#puts [format "DEFAULT code_coverage_enable : %s" $ini(code_coverage_enable)]

## The $builddict dictionary contains the following sub-structure:
##  { <testbench_name> }
##      - { buildcmd } : Extra command-line arguments to use during 'make build' command
##      - { elabcmd } : Extra command-line arguments to use during 'make elab' command
##      - { runcmd } : Extra command-line arguments appended to vsim command for this testbench
##      - { builddir } : Directory where this testbench's Makefile lives      
##      - { symlinks } : List of symbolic links to create for each test executed. Only defined by YAML testlist
##  { <repeated for all testbenches> }

## $tcdict organization to allow for per-iteration extra-args
##  { <testbench_name> }
##     { <testcase_name> }
##        { Iteration# } : Incrementing from 0 to N
##          { seed } : Seed to use for this iteration
##          { extra_args } : Extra command-line arguments for this iteration
##          { uvm_testname } : UVM test to invoke. Only defined by YAML testlist

def initPy(rd, master_seed=0, dbg=0):
    global file_read
    global root_dir
    global debug
    global ini
    global rerun_count
    global mseed
    
    debug = dbg
    file_read = 0
    root_dir = rd
    
    if master_seed == "random":
        logger.info("NOTE: Using random master seed")
        ms = int(time.time())
    else:
        logger.info("NOTE: Using fixed random seed")
        ms = master_seed
    
    random.seed(ms)
    mseed = ms
    
    logger.info(f"NOTE: Master seed set to {ms}")
    
    vrmSetupDefaults()
    vrmSetup()
    
    #if debug == 1:
    logger.info("DEBUG: Initialization variable settings:")
    dumpIniVars()
    
    rerun_count = 0
    
    return 0

## Default proc is empty - expectation is that user points to a separate
## file pointed to by $UVMF_VRM_INI env variable to override this proc
## and fill it with desired overrides to default behavior. That Tcl is 
## sourced early enough that other procs (to define non-standard LSF, for
## example) can be defined as well
def vrmSetup():
    pass

def vrmSetupDefaults():
    global root_dir
    setIniVar("testlist_name", "testlist", 1)
    setIniVar("top_testlist_file", "(%SIM_DIR%)/(%TESTLIST_NAME%)", 1)
    setIniVar("code_coverage_enable", 0, 1)
    setIniVar("code_coverage_types", "bsf", 1)
    setIniVar("code_coverage_target", "/hdl_top/DUT.", 1)
    setIniVar("code_coverage_map", 0, 1)
    setIniVar("extra_merge_options", "", 1)
    setIniVar("extra_run_options", "", 1)
    setIniVar("tplanfile", "", 1)
    setIniVar("tplanoptions", "-format Excel", 1)
    setIniVar("tplan_merge_options", "-testassociated", 1)
    setIniVar("no_rerun", 1, 1)
    setIniVar("rerun_limit", 0, 1)
    setIniVar("use_infact", 0, 1)
    setIniVar("use_vis", 0, 1)
    setIniVar("use_vinfo", 0, 1)
    setIniVar("dump_waves", 0, 1)
    setIniVar("dump_waves_on_rerun", 0, 1)
    setIniVar("vis_dump_options", "+signal+report+memory=512", 1)
    setIniVar("exclusionfile", "", 1)
    setIniVar("pre_run_dofile", "{''}", 1)
    setIniVar("pre_vsim_dofile", "{''}", 1)
    setIniVar("run_exec", "", 1)
    setIniVar("use_test_dofile", 0, 1)
    setIniVar("use_job_mgmt_run", 0, 1)
    setIniVar("use_job_mgmt_build", 0, 1)
    setIniVar("use_job_mgmt_covercheck", 0, 1)
    setIniVar("use_job_mgmt_exclusion", 0, 1)
    setIniVar("use_job_mgmt_report", 0, 1)
    setIniVar("gridtype", "lsf", 1)
    # Use of older switches "-source" and "-htmldir" have been replaced with "-annotate" and "-output" respectively.
    # May need to use this alternative set of switches if using an older release of Questa
    # setIniVar("html_report_args", "-details -source -testdetails -showexcluded -htmldir (%VRUNDIR%)/covhtmlreport", 1)
    setIniVar("html_report_args", "-details -annotate -testdetails -showexcluded -output (%VRUNDIR%)/covhtmlreport", 1)
    setIniVar("gridcommand_run", "bsub -J (%INSTANCE%) -oo (%TASKDIR%)/(%SCRIPT%).o%J -eo (%TASKDIR%)/(%SCRIPT%).e%J (%WRAPPER%)", 1)
    setIniVar("gridcommand_build", "bsub -J (%INSTANCE%) -oo (%TASKDIR%)/(%SCRIPT%).o%J -eo (%TASKDIR%)/(%SCRIPT%).e%J (%WRAPPER%)", 1)
    setIniVar("gridcommand_covercheck", "bsub -J (%INSTANCE%) -oo (%TASKDIR%)/(%SCRIPT%).o%J -eo (%TASKDIR%)/(%SCRIPT%).e%J (%WRAPPER%)", 1)
    setIniVar("gridcommand_exclusion", "bsub -J (%INSTANCE%) -oo (%TASKDIR%)/(%SCRIPT%).o%J -eo (%TASKDIR%)/(%SCRIPT%).e%J (%WRAPPER%)", 1)
    setIniVar("gridcommand_report", "bsub -J (%INSTANCE%) -oo (%TASKDIR%)/(%SCRIPT%).o%J -eo (%TASKDIR%)/(%SCRIPT%).e%J (%WRAPPER%)", 1)
    setIniVar("use_covercheck", 0, 1)
    setIniVar("top_du_name", "top_du_name", 1)
    setIniVar("covercheck_build", "covercheck_build", 1)
    setIniVar("extra_covercheck_options", "", 1)
    setIniVar("covercheck_analyze_timeout", "15m", 1)
    setIniVar("covercheck_init_file", "", 1)
    setIniVar("covercheck_ucdb_file", "(%DATADIR%)/tracker.ucdb", 1)
    setIniVar("timeout", 3600, 1)
    setIniVar("queue_timeout", 60, 1)
    setIniVar("build_timeout", -1, 1)
    setIniVar("build_queue_timeout", -1, 1)
    setIniVar("run_timeout", -1, 1)
    setIniVar("run_queue_timeout", -1, 1)
    setIniVar("exclusion_timeout", -1, 1)
    setIniVar("exclusion_queue_timeout", -1, 1)
    setIniVar("covercheck_timeout", -1, 1)
    setIniVar("covercheck_queue_timeout", -1, 1)
    setIniVar("report_timeout", -1, 1)
    setIniVar("report_queue_timeout", -1, 1)
    setIniVar("email_servers", {}, 1)
    setIniVar("email_recipients", {}, 1)
    setIniVar("email_sections", "all", 1)
    setIniVar("email_subject", {}, 1)
    setIniVar("email_message", {}, 1)
    setIniVar("email_originator", {}, 1)
    setIniVar("usestderr", 0, 1)
    setIniVar("trendfile", {}, 1)
    setIniVar("trendoptions", {}, 1)
    setIniVar("triagefile", {}, 1)
    setIniVar("triageoptions", {}, 1)
    setIniVar("use_bcr", 0, 1)
    setIniVar("bcr_exec_cmd_linux", "uvmf_bcr.py", 1)
    setIniVar("bcr_exec_cmd_windows", "python $::env(UVMF_HOME)/scripts/uvmf_bcr.py", 1)
    setIniVar("bcr_flow", "questa", 1)
    setIniVar("bcr_overlay", {}, 1)
    setIniVar("multiuser", 1, 1)
    return 0
    
def get_timeout_val(global_timeout, timeout):
    if timeout == -1:
        return global_timeout
    else:
        return timeout

def getIniVar(varname):
    global ini, debug
    lv = varname.lower()
    if lv in ini:
        #if debug:
        logger.info("DEBUG: ini variable {0} returning value '{1}'".format(varname, ini[lv]))
        return ini[lv]
    return {}
    # logger.error(": ini variable {0} not found".format(varname))
    # logger.info("Available ini variables: {0}".format(list(ini.keys())))
    # exit(88)

def setIniVar(varname, value, firsttime=0):
    global ini
    global debug
    #if debug == 1:
    logger.info(f"DEBUG: ini variable \"{varname}\" getting set to \"{value}\"")
    lv = varname.lower()
    if firsttime == 0:
        if lv not in ini:
            available_vars = '\n\t'.join(ini.keys())
            logger.error(f": ini variable \"{varname}\" unrecognized on set attempt. Following list are available:\n\t{available_vars}")
            raise SystemExit(88)
    ini[lv] = value

def dumpIniVars():
    global ini
    for key, value in ini.items():
        logger.info(" {} = {}".format(key, value))

def getInfactSdmIni(datadir):
    use_infact = ini.get('use_infact')
    if use_infact:
        return os.path.join("+infact=" + datadir, "infactsdm_info.ini")
    else:
        return ""

def ReadYAMLTestlistFile(file_name, invoc_dir, collapse=0, debug=0, init=0):
    global testlist_info
    global tcdict
    global builddict
    global root_dir
    global recursion_check
    global current_tb
    #filename = os.path.normpath(file_name)
    ## Resolve full path to file name
    filename = resolve_path(file_name,os.getcwd())
    logger.info(f": Reading YAML testlist file \"{filename}\"")
    logger.debug(f": Reading recursion_check \"{recursion_check}\"")
    if not os.path.isfile(filename):
        logger.error(f": Invalid file - {filename}")
        exit(88)
    if filename in recursion_check:
        logger.error(f": Circular recursion detected in YAML testlist file {filename}, was included earlier in {recursion_check}")
        exit(88)
    #for i,fname in enumerate(recursion_check):
    #    if filename == recursion_check[i]:
    #      logger.error(f": Circular recursion detected in YAML testlist file {filename}, was included earlier")
    #      logger.error(f": Circular recursion detected in YAML testlist file {recursion_check[i]}, was included earlier")
    #      exit(88)
    with open(filename, "r") as f:
        yaml_data = yaml.safe_load(f)
    logger.debug("yaml_data info:\n{}".format(yaml_data))
    recursion_check.append(filename)
    if "uvmf_testlist" not in yaml_data.keys():
        logger.error(f": testlist YAML file {filename} formatting error")
        exit(88)
    # find the _compile.yaml from _testlist.yaml
    dir_name = os.path.dirname(filename)
    if "testbenches" in yaml_data["uvmf_testlist"]:
        for tb in yaml_data["uvmf_testlist"]["testbenches"]:
            if "name" not in tb:
                logger.error(f": testlist YAML file {filename} formatting error")
                exit(88)
            #if debug:
            logger.info(f"DEBUG: Adding testbench {tb['name']} info to list")
            tb_name = tb["name"]
            if tb_name in builddict:
                logger.error(f": Testbench \"{tb_name}\" registered twice")
                exit(88)
            tb.setdefault("extra_build_options", "")
            tb.setdefault("extra_elab_options", "")
            tb.setdefault("extra_run_options", "")
            tb.setdefault("symlinks", "")
            builddict[tb_name] = {"buildcmd": tb["extra_build_options"],
                                  "elabcmd": tb["extra_elab_options"],
                                  "runcmd": tb["extra_run_options"],
                                  "symlinks": tb["symlinks"],
                                  "builddir": dir_name}
            #if debug:
            logger.info(f"DEBUG: Registering testbench {tb_name}")
            logger.info(f"DEBUG:   buildcmd: {tb['extra_build_options']}")
            logger.info(f"DEBUG:   elabcmd: {tb['extra_elab_options']}")
            logger.info(f"DEBUG:   runcmd: {tb['extra_run_options']}")
            logger.info(f"DEBUG:   symlinks: {tb['symlinks']}")
            logger.info(f"DEBUG:   builddir: {dir_name}")
            testlist_info.append(tb)

    #logger.debug("yaml_data info:\n{}".format(yaml_data))
    if 'uvmf_testlist' in yaml_data and 'tests' in yaml_data['uvmf_testlist']:
        for test in yaml_data['uvmf_testlist']['tests']:
            logger.debug("test info:\n{}".format(test))
            if 'testbench' not in test and 'name' not in test:
                logger.error(": YAML test entry is invalid, no testbench or name entry found")
                exit(88)
            if 'testbench' in test:
                current_tb = test['testbench']
            logger.debug("current_tb info:\n{}".format(current_tb))
            if 'name' in test:
                tname = test['name']
                tname = tname.replace('-', '_')
                if current_tb == '':
                    logger.error(": No testbench specified when encountered test \"{}\"".format(tname))
                    exit(88)
                # Remaining items in entry are optional:
                #  repeat count (default 1)
                #  seed list (default random)
                #  uvm testname (default same as test name)
                #  extra arguments (default empty)
                # It is possible that there are already test entries for this test, meaning that
                #  our iteration count doesn't always start at 0. Search the current test case
                #  dictionary for the current name as a first pass to determine our starting iteration
                #  number for this series of entries
                if current_tb not in tcdict:
                    tcdict[current_tb] = {}
                if tname not in tcdict[current_tb]:
                    tcdict[current_tb][tname] = {}
                    firstiter = 0
                else:
                    firstiter = len(tcdict[current_tb][tname].keys())
                
                if "repeat" not in test:
                    repcount = 1
                else:
                    repcount = test["repeat"]
                
                if "seeds" not in test:
                    seedlist = []
                else:
                    seedlist = test["seeds"]
                
                while len(seedlist) < repcount:
                    seedlist.append(random.randint(0, 1000000))
                
                for rep in range(repcount):
                    if seedlist[rep] == "random":
                        seedlist[rep] = random.randint(0, 1000000)
                
                if "uvm_testname" not in test:
                    uvm_testname = tname
                else:
                    uvm_testname = test["uvm_testname"]
                
                if "extra_args" not in test:
                    extra_test_options = ""
                else:
                    extra_test_options = test["extra_args"]
                
                logger.debug("current_tb info:\n{}".format(current_tb))
                logger.debug("tname info:\n{}".format(tname))
                logger.debug("firstiter info:\n{}".format(firstiter))
                logger.debug("tcdict info:\n{}".format(tcdict))
                for seed in seedlist:
                    tcdict[current_tb][tname][firstiter] = {"seed": seed, "extra_args": extra_test_options, "uvm_testname": uvm_testname}
                    firstiter += 1
                
    if 'uvmf_testlist' in yaml_data and 'include' in yaml_data['uvmf_testlist']:
        for inc in yaml_data['uvmf_testlist']['include']:
            if inc not in recursion_check:
                frame = inspect.currentframe()
                method_name = inspect.getframeinfo(frame).function
                norm_file = resolve_path(inc, dir_name, file_name)
                logger.info("DEBUGMIR function  \"{}\" \n \"{}\" \n".format(method_name, norm_file))
                ReadYAMLTestlistFile(norm_file, invoc_dir, collapse, debug, False)
                recursion_check.append(norm_file)
    #if collapse:
    #    test_list = []
    #    for tb in tcdict:
    #        for name in tcdict[tb]:
    #            for iter_num in tcdict[tb][name]:
    #                test = tcdict[tb][name][iter_num]
    #                test['testbench'] = tb
    #                test['name'] = name
    #                test_list.append(test)
    #    tcdict = test_list
    #return tcdict
    logger.info(f"DEBUG: Finished with file \"{file_name}\"")
    print_builddict()

# helper function to generate random integer seeds
def randInt():
    return random.randint(0, (1 << 31) - 1)

## Top level test list parser invocation.  Sets up some globals and then
## fires off the internal reader (for purposes of nesting)
def ReadTestlistFile (file_name, invoc_dir, collapse=0, debug=0, init=0):
    global recursion_check
    global tcdict
    global builddict
    global file_read
    global current_tb
    if file_read == 1:
        return ""
    tcdict = {}
    builddict = {}
    testlist_info = {}
    current_tb = ""
    if os.path.splitext(file_name)[1] == ".yaml":
        ReadYAMLTestlistFile(file_name, invoc_dir, collapse, debug)
    else:
        ReadTestlistFile_int(file_name, invoc_dir, collapse, debug)
    if debug == 1:
        logger.info_tcdict()
    file_read = 1
    return ""

def print_tcdict():
    global tcdict
    logger.info("DEBUG: tcdict contents:")
    for top, testnames in tcdict.items():
        logger.info(f'Testbench : "{top}"')
        for test, iter in testnames.items():
            logger.info(f'\t- Test : "{test}"')
            for i, values in iter.items():
                extra_args = values.get('extra_args', '')
                ea_str = f'- Extra Args : "{extra_args}"' if extra_args else ''
                logger.info(f'\t\t- {i} - UVM Test: {values.get("uvm_testname")} - Seed : {values.get("seed")} {ea_str}')

def print_builddict():
    global builddict
    if "builddict" not in globals():
        return
    for buildname, entry in builddict.items():
        logger.info(f"{buildname} - {entry}")

def get_map_info(build_name, key):
    global builddict
    if build_name not in builddict:
        logger.error(f" getMapInfo - build {build_name} invalid")
        exit()
    if "mapinfo" not in builddict[build_name]:
        return ""
    return builddict[build_name]["mapinfo"].get(key)

#def process_yaml_test_entry(entry, debug=1):
#    global builddict
#    global tcdict
#    global current_tb
#    if 'testbench' in entry:
#        current_tb = entry['testbench']
#        if debug:
#            logger.info(f"DEBUG: Setting current testbench to {current_tb}")
#    elif not current_tb:
#        logger.error(": No testbench setting found before encountering test entries")
#        exit(88)

def ex(code):
    sys.exit(code)

## Actual test list file reader.  See embedded comments for more detail
def ReadTestlistFile_int (file_name, invoc_dir, collapse, debug=1, init=0):
    global recursion_check
    global tcdict
    global builddict
    global root_dir
    tops = ""
    # Elaborate "^" at beginning of file_name and expand with root_dir
    if file_name.startswith('^'):
        file_name = os.path.join(root_dir, file_name[1:])
    # Derive full path for filename
    file_name = os.path.abspath(file_name)
    # Recursion is checked for, i.e. if a test list includes itself
    if file_name in recursion_check:
        logger.error(f"RECURSION: {file_name}")
        exit(88)
    logger.info(f"NOTE: Reading testlist file \"{file_name}\"")
    recursion_check.append(file_name)
    if not os.path.isfile(file_name):
        logger.error(f"INVALID FILE: {file_name}")
        exit(88)
    dir = os.path.dirname(file_name)
    with open(file_name, 'r') as tfile:
        for line in tfile:
            # Skip comment lines in testlist file - first column a # sign
            if not line.startswith('#'):
                # Skip whitespace
                if len(line.split()) != 0:
                    # Process TB_INFO lines, which has information regarding how to
                    # build a particular testbench
                    if line.split()[0] == "TB_INFO":
                        if len(line.split()) != 4:
                            logger.error(f"TB_INFO ARGS: {line}")
                            exit(88)
                        builddict[line.split()[1]] = {
                            "buildcmd": line.split()[2],
                            "elabcmd": line.split()[3],
                            "runcmd": line.split()[4],
                            "symlinks": "",
                            "builddir": dir
                        }
                        #if debug==1:
                        logger.info(f"DEBUG: Registering testbench {line.split()[1]}")
                        logger.info(f"DEBUG:   buildcmd: {line.split()[2]}")
                        logger.info(f"DEBUG:   elabcmd: {line.split()[3]}")
                        logger.info(f"DEBUG:   runcmd: {line.split()[4]}")
                        logger.info(f"DEBUG:   builddir: {dir}")
                    # Process TB_LOCATION lines which can override the default builddir entry for this bench.
                    # This allows some flexibility into where the test list lives vs. where the bench's ./sim directory
                    # exists, and should be specified when the test list exists outside of the ./sim directory
                    elif line.split()[0] == "TB_LOCATION":
                        if len(line.split()) != 3:
                            logger.error(f"TB_LOCATION ARGS: {line}")
                            exit(88)
                        if line.split()[1] not in builddict:
                            logger.error(f"TB_LOCATION - No TB_INFO entry for {line.split()[1]}")
                            logger.info_builddict()
                            exit(88)
                        builddict[line.split()[1]]["builddir"] = line.split()[2]
                        #if debug==1:
                        logger.info(f"DEBUG: Setting builddir for {line.split()[1]} as {line.split()[2]}")
                    # Process TB_MAP lines, which must contain three arguments after the keyword
                    # The three arguments should be the testbench name, followed by the source hierarchy, then the destination hierarchy
                    elif line.split()[0] == "TB_MAP":
                        if len(line.split()) != 4:
                            logger.error(f"TB_MAP ARGS : {line}")
                        if not builddict or line.split()[1] not in builddict:
                            logger.error(f"TB_MAP - No TB_INFO entry for {line.split()[1]}")
                            print_builddict()
                            return 88
                        source_hier = line.split()[2].strip().split("/")
                        dest_hier = line.split()[3].strip().split("/")
                        builddict[line.split()[1]]["mapinfo"]["blockpath"] = "/".join(source_hier[:-1])
                        builddict[line.split()[1]]["mapinfo"]["blockleaf"] = source_hier[-1]
                        builddict[line.split()[1]]["mapinfo"]["syspath"] = "/".join(dest_hier[:-1])
                        builddict[line.split()[1]]["mapinfo"]["sysleaf"] = dest_hier[-1]
                    # Process TB lines, which should contain a unique build label
                    elif line.split()[0] == "TB":
                        if len(line.split()) != 2:
                            logger.error(f"TB ARGS : {line}")
                            return 88
                        if not builddict or line.split()[1] not in builddict:
                            logger.error(f"TB - No TB_INFO entry for {line.split()[1]}")
                            print_builddict()
                            return 88
                        tops = line.split()[1]
                        #if debug == 1:
                        logger.info(f"DEBUG: Current top \"{tops}\"")
                    # Process TEST lines, which will be stored according to the last TB seen
                    # Each TEST line contains a test name, a repeat count, and some number of
                    # seeds. Optional last item on a TEST line is a string of additional vsim 
                    # args to be used for just that test.
                    # If the test name contains DASHES those are converted to UNDERSCORES because
                    # the system uses dashes internally
                    elif line.startswith("TEST"):
                        if len(tops) == 0:
                            logger.error(f"TEST NO TOP SPECIFIED : {line}")
                            raise SystemExit(88)
                        if len(line.split()) == 1:
                            logger.error(f"TEST NOT ENOUGH ARGS : {line}")
                            raise SystemExit(88)
                        
                        # Pull off final extra vsim args if possibly present
                        extra_test_vsim_args = ""
                        if len(line.split()) > 2:
                            if not line.split()[-1].isnumeric():
                                # Last item on the line wasn't a random seed, therefore it is vsim args
                                # Remove item from the list before further processing
                                extra_test_vsim_args = line.split()[-1]
                                line = line.split()[:-1]
                                #if debug:
                                logger.info(f"DEBUG: Detected additional plusarg \"{extra_test_vsim_args}\" for test \"{line[1]}\"")
                        
                        else:
                            extra_test_vsim_args = ""
                        
                        # Extract test name from line
                        tname = line.split()[1]
                        # Convert dashes to underscores if found
                        tname = tname.replace("-", "_")
                        # Store UVM test name as the test name (forward compat)
                        uvm_tname = tname
                        
                        # Extract repeat count from line. If unspecified default to 1
                        if len(line.split()) == 2:
                            repcount = 1
                        else:
                            repcount = int(line.split()[2])
                        #!<## Extract repeat count from line. If unspecified default to 1
                        #!<if len(line) == 2:
                        #!<    repcount = 1
                        #!<else:
                        #!<    repcount = int(line[2])
                        ## Extract seeds from line. May contain between 0 and $repcount seeds
                        ## If any are unspecified default to internally generated random unless
                        ## $collapse is specified in which we ignore the repeat count and fix 
                        ## the seed to zero.
                        seedlist = []
                        iterlist = []
                        if collapse == 0:
                            for repeat in range(repcount):
                                if line[repeat + 3] == "":
                                    seedlist.append(str(int(random.random() * 10000000000000000) % 4294967296))
                                else:
                                    seedlist.append(line[repeat + 3])
                                iterlist.append(repeat)
                        else:
                            seedlist.append("0")
                            iterlist.append("0")
                        
                        ## Now build up the $tcdict entries for this line
                        if tops not in tcdict or tname not in tcdict[tops]:
                            ## First time we've seen this test so create a new entry
                            #if debug == 1:
                            logger.info(f"DEBUG: Creating initial entry for test \"{tname}\"")
                            firstiter = 0
                        else:
                            ## Not the first time we've seen this test, figure out where to start
                            ## appending more iterations
                            firstiter = len(tcdict[tops][tname].keys())
                            #if debug == 1:
                            logger.info(f"DEBUG: Adding extra entries starting at {firstiter} for test \"{tname}\"")
                        
                        for seed in seedlist:
                            tcdict[tops][tname][firstiter] = {"seed": seed, "extra_args": extra_test_vsim_args, "uvm_testname": uvm_tname}
                            firstiter += 1
                        #if debug == 1:
                        logger.info(f"DEBUG: Added {len(seedlist)} test \"{tname}\" for build \"{tops}\"")

                    ##
                    ## Process INCLUDE lines, which is another file to parse.  
                    ##
                    elif line[0] == "INCLUDE":
                        #if debug == 1:
                        logger.info(f"DEBUG: Including file {line[1]}")
                        ReadTestlistFile_int(line[1], invoc_dir, collapse, debug)
   
    recursion_check = recursion_check[:-1]
    #if debug == 1:
    logger.info(f"DEBUG: Finished with file \"{file_name}\"")
    print_builddict() 

# Called by the runnables, returns a list of testbenches to
# build, produces the top-level of runnable hierarchy  
def GetBuilds():
    global tcdict
    return list(tcdict.keys())

# Called by the runnables, returns the build command unique to
# this particular build.
def GetBuildCmd(build):
    global builddict
    return builddict[build]["buildcmd"]

# Called by the runnables, returns the elab command unique to
# this particular build.
def GetElabCmd(build):
    global builddict
    return builddict[build]["elabcmd"]

# Called by the runnables, returns the run command for this particular build.
def GetRunCmd(build):
    global builddict
    return builddict[build]["runcmd"]

def GetBuildDir(build):
    global builddict
    return builddict[build]["builddir"]

# Returns extra arguments for a given test. The full testname
# is expected to be passed in as per standard format
# <benchname>-<tesname>-<iter>-<seed> so that'll need to be split
# out in order to extract info from the test case dictionary
def GetExtraArgs(testname):
    global tcdict
    rv = testname.split("-")
    return tcdict[rv[0]][rv[1]][rv[2]]["extra_args"]

def GetUVMTestname(testname):
    global tcdict
    rv = testname.split("-")
    ret = tcdict[rv[0]][rv[1]][rv[2]]["uvm_testname"]
    return ret

def GetTestcases(build, collapse=False):
    global tcdict
    ret = []
    for test, test_info in tcdict[build].items():
        for i in test_info.keys():
            ret.append(f"{build}-{test}-{i}-{test_info[i]['seed']}")
    if collapse:
        test_list = []
        #for tb in tcdict:
        for name in tcdict[build]:
            for iter_num in tcdict[build][name]:
                test = tcdict[build][name][iter_num]
                test['testbench'] = build
                test['name'] = name
                test_list.append(test)
        ret = test_list
    #return tcdict
    return ret

def FindMVCHome(Makefile_name):
    if not os.path.exists(Makefile_name):
        return 0
    matchcnt = len(fileinput.input(files=Makefile_name).grep("mvchome"))
    return matchcnt

def OkToMerge(userdata):
    data = userdata
    passfail = data['passfail']
    ucdbfile = data['ucdbfile']
    if not os.path.exists(ucdbfile):
        return 0
    if passfail != 'passed':
        subprocess.call(f"vsim -c -viewcov {ucdbfile} -do 'coverage edit -keeponly -assert; coverage save {ucdbfile}; quit'", shell=True)
    return 1

def OkToRerun(userdata):
    global rerun_count, rerun_limit, RunOptns
    
    data = userdata['data']
    
    # Get the latest reason for failure from the history list
    reason = data['HISTORY'][-1]
    
    # Queue timeouts, launch failures, and retry requests are always re-run as-is until they exceed the global limit...
    alwaysRerun = [
        ['failed', 'launch'],
        ['failed', 'retry'],
        ['timeout', 'queued']
    ]
    
    if reason in alwaysRerun:
        return True
    
    # ...unless disabled, mergeScripts and triageScripts are always re-run as-is until they exceed the global limit...
    if mergeRerun and data['ROLE'] in ['mergeScript', 'triageScript']:
        return True
    
    # ...other execScript failures are re-run until they've occured twice overall
    # (a debug message is squawked only if the re-run is suppressed)
    if data['ROLE'] == 'execScript':
        action = data['ACTION']
        # Re-run only 1st failure of any given type (to pick up the debug-mode run)
        samefails = [i for i, h in enumerate(data['HISTORY']) if h == reason]
        if len(samefails) > 1:
            if isDebug():
                logDebug("OkToRerun: Multiple failures, rerun suppressed")
            return False
        # Don't re-run if the DEBUGMODE parameter is undefined or blank
        debugmode = ExpandRmdbParameters(action, "(%DEBUGMODE:%)")
        if debugmode == '':
            if isDebug():
                logDebug("OkToRerun: No DEBUGMODE parameter, rerun suppressed")
            return False
        # Don't re-run if the DEBUGMODE parameter is already enabled
        if debugmode in ['yes', 'true', '1']:
            if isDebug():
                logDebug("OkToRerun: DEBUGMODE parameter already enabled, rerun suppressed")
            return False
        # UVMF - If the current rerun count is equal to the rerun_limit (and rerun_limit)
        # is > 0, don't rerun
        rerun_limit = getIniVar('rerun_limit')
        if rerun_limit > 0 and rerun_count >= rerun_limit:
            if isDebug():
                logDebug("OkToRerun: Rerun count reached limit, rerun suppressed")
            return False
        # Override the DEBUGMODE parameter to indicate an error re-run...
        if debugmode == 'no':
            OverrideRmdbParameter(action, 'DEBUGMODE', 'yes')
        elif debugmode == 'false':
            OverrideRmdbParameter(action, 'DEBUGMODE', 'true')
        else:
            OverrideRmdbParameter(action, 'DEBUGMODE', '1')
        # UVMF - increment the global rerun_count variable
        rerun_count += 1
        # ...then, flag the Action for another run
        return True
    
    if isDebug():
        logDebug("OkToRerun: Not timeout and not execScript, rerun suppressed")
    return False  # just in case -- shouldn't reach here

def GetCodeCovBuildString(bcr, enable, types, target):
    if enable:
        if bcr:
            str = "code_cov_enable:True"
            if types != "":
                str += " code_cov_types:" + types
            if target != "":
                str += " code_cov_target:" + target
        else:
            str = "CODE_COVERAGE_ENABLE=1"
            if types != "":
                str += " CODE_COVERAGE_TYPES=" + types
            if target != "":
                str += " CODE_COVERAGE_TARGET=" + target
    else:
        str = ""
    return str

def GetCodeCovRunString(bcr, enable):
    if enable:
        if bcr:
            str = "code_cov_enable:True"
        else:
            str = "-coverage"
    else:
        str = ""
    return str


def GetVisArgs(bcr, use_vis, dump_waves, debugmode, no_rerun, dump_waves_on_rerun, vis_dump_options):
    if use_vis and (dump_waves or (debugmode and not no_rerun and dump_waves_on_rerun)):
        if bcr:
            return f"use_vis:True vis_wave:{vis_dump_options}"
        else:
            return f"-qwavedb={vis_dump_options}"
    else:
        return ""

## This will run at the start of the regression and will bail out IMMEDIATELY if any of the "use_job_mgmt" INI
## variables are set and the "gridtype" variable is not explicitly cleared. This is a workaround for VM-12996
def RegressionStarting(userdata={}):
    data = userdata
    usingGrid = (getIniVar("use_job_mgmt_run") or
                 getIniVar("use_job_mgmt_build") or
                 getIniVar("use_job_mgmt_covercheck") or
                 getIniVar("use_job_mgmt_exclusion") or
                 getIniVar("use_job_mgmt_report"))
    gridtypeIniVar = getIniVar("gridtype")
    if "UVMF_VRM_INI" in os.environ:
        iniFile = os.environ["UVMF_VRM_INI"]
    else:
        iniFile = "./uvmf_vrm_ini.tcl"
    if gridtypeIniVar and usingGrid:
        logger.info("\n\n**********************************************************************************************************")
        logger.error(": Stopping regression at {} due to setting one of the 'use_job_mgmt' variables in '{}'".format(RightNow(), iniFile))
        logger.info("Please set the 'gridtype' variable the INI file to an empty string and set the gridtype in the RMDB method directly:")
        logger.info("e.g. change this:")
        logger.info('  <method if="(%USE_JOB_MGMT_BUILD%)" gridtype="(%GRIDTYPE%)" mintimeout="(%BUILD_QUEUE_TIMEOUT%)">')
        logger.info("to this:")
        logger.info('  <method if="(%USE_JOB_MGMT_BUILD%)" gridtype="lsf" mintimeout="(%BUILD_QUEUE_TIMEOUT%)"> <!-- or sge, rtda, etc..-->')
        logger.info("**********************************************************************************************************\n\n")
        raise SystemExit(88)
        # subprocess.run([data["VSIMDIR"]+"/vrun", "-exit", "-rmdb", data["RMDBFILE"], "-vrmdata", data["DATADIR"]])
    logger.info("Regression started at {}...".format(RightNow()))
    #os.chdir(data['tb'] + '/__COMPILE__') # .../sim/tdir/folder_path
    logger.debug('Executing in {},'.format(os.getcwd()))
    #uvmf_bcr.args.yaml_dir = '{}'.format(data['builddir']) + ' --build_dir ' + '{}'.format(data['tb']);
    ##!<uvmf_bcr.run()
    cmd = 'c:\\msys64\\mingw64/bin/python.exe ' + os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+'/scripts/'+'uvmf_bcr.py ' + ' 3step ' + '  --steps compile '
    logger.debug("Executing flow \"{}\" step \"{}\" commands:\n  {}".format('3step','compile', cmd))
    ##!< if os.path.exists('c:\\msys64\\mingw64/bin/python.exe '):
    ##!<     logger.debug("path exists")
    ##!< if os.path.exists(os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+'/scripts/'+'uvmf_bcr.py '):
    ##!<     logger.debug("path exists")
    ##!< output = os.system(cmd)
    output = subprocess.call(cmd, shell=True)
    logger.debug(output)
    cmd = 'c:\\msys64\\mingw64/bin/python.exe ' + os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+'/scripts/'+'uvmf_bcr.py ' + ' 3step ' + '  --steps optimize '
    logger.debug("Executing flow \"{}\" step \"{}\" commands:\n  {}".format('3step','elab', cmd))
    output = subprocess.call(cmd, shell=True)
    logger.debug(output)

def RegressionRunStarting(userdata={}):
    data = userdata
    logger.debug("list of testcases to run {}".format(userdata))
    for i,item in enumerate(data):
        logger.debug("testcase to run {}".format(GetTestcases(item['testbench'])[i]))
        logger.debug("Simulation {} starting on {}".format(i, item))
        ##!< folder_path = item['testbench'] + '/' + GetTestcases(item['testbench'])[i]
        ##!< if not os.path.exists(folder_path) : 
        ##!<     logger.info('Create the folder = {}'.format(folder_path))
        ##!<     os.makedirs(folder_path)    
        ##!< cmd = 'cp -r ' + ' {}'.format(item['testbench'] + '/__COMPILE__/xcelium.d/ ') + ' {}/'.format(folder_path)
        ##!< logger.debug('Running ... {}'.format(cmd))
        ##!< subprocess.call(cmd, shell=True)
        ##!< os.chdir(item['testbench'] + '/' + GetTestcases(item['testbench'])[i]) # .../sim/tdir/folder_path
        ##!< cmd = 'xrun -R ' + '-l sim.log -svseed {}'.format(item['seed']) + ' +UVM_TESTNAME={}'.format(item['uvm_testname']) + ' {}'.format(item['extra_args']) + ' {}'.format(GetRunCmd(item['testbench']))  
        ##!< logger.debug('Running ... {}'.format(cmd))
        ##!< #subprocess.call(cmd, shell=True)
        ##!< #subprocess.check_output(cmd, shell=True)
        cmd = 'c:\\msys64\\mingw64/bin/python.exe ' + os.path.dirname(os.path.dirname(os.path.realpath(__file__)))+'/scripts/'+'uvmf_bcr.py ' + ' 3step ' + '  --steps run ' + "test:" + '{}'.format(item['uvm_testname'])
        logger.debug("Executing flow \"{}\" step \"{}\" commands:\n  {}".format('3step','run', cmd))
        ##!< sys.exit(0)
        ##!< subprocess.call(cmd, shell=True)
        try:
           proc = subprocess.Popen(cmd,
                                 shell = True) 
           ''',
                                 executable = "/bin/bash",
                                 stdout=None,
                                 stderr=None'''
        except subprocess.CalledProcessError:
           (simulation_lines_str,err_str) = proc.communicate()
           logger.error('in simulation_stdout: {0}'.format(err_str))
           sys.exit(1)
        
        except KeyboardInterrupt :
           logger.info("\nExited Ctrl-C from user request.")
           sys.exit(130)
        ##!< os.chdir('../../') # .../sim/tdir/folder_path
    while proc.poll() is None:
        # Process is still running
        # You can perform some other tasks here
        pass  
    ##!< cmd = ' {}'.format("c:\\msys64\\mingw64/bin/python.exe  Bucketizer.py")
    ##!< logger.debug('Running ... {}'.format(cmd))
    ##!< subprocess.call(cmd, shell=True)  
    
def GenSymlinks(vrundir, taskdir, build, debug):
    global builddict
    for link in builddict[build]["symlinks"]:
        target = os.path.normpath(link[0])
        dest = os.path.normpath(os.path.join(taskdir, link[1]))
        #if debug:
        logger.info("DEBUG: Creating symbolic link {} -> {}".format(target, dest))
        os.symlink(target, dest)
    return "# Generating symbolic links from testlist file"

if __name__ == '__main__':
  local_tblist =[]
  userdata = {}
  logger = logging.getLogger("logger")
  logger.debug("Python version info:\n"+sys.version)
  cur_path = os.getcwd()
  ##!<setup_env(cur_path)
  ##!< initPy(os.environ["TRUNK"] + '/' + os.environ["WSP"] + '/common/yaml/')
  ##!< ReadTestlistFile(os.environ["TRUNK"] + '/' + os.environ["WSP"] + '/common/yaml/' + "master.yaml", ".")
  ReadTestlistFile("bcr_testlist.yaml", ".")
  #ReadTestlistFile_int("/workspace/Persons/aliabbasmir/CAD/cad_dev/dv_tools/DVS/demo/trunk/alu_ss/common/yaml/bcr_testlist.yaml", ".", 0)
  print_tcdict()
  print_builddict()
  local_tblist = GetBuilds()
  logger.debug(" {}".format(GetBuilds()))
  for tb in local_tblist:
    logger.debug("BuildCmd to run {}".format(GetBuildCmd(tb)))
    userdata['tb'] = tb
    userdata['builddir'] = GetBuildDir(tb)
    RegressionStarting(userdata)
  for tb in local_tblist:
    logger.debug("RunCmd to run {}".format(GetRunCmd(tb)))
    userdata = GetTestcases(tb, True)
    RegressionRunStarting(userdata)
  logger.debug("End of simulation ") 
      

