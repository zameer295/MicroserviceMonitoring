"""
 This script collects a bunch of system data and generates
 compressed reports. Another script (sysreport.py) reads this 
 data and creates plots.

 Parameters reported currently include - 
    (Statistics : report-filename)
    * Per process statistics                          : process_yymmdd_hhmmss
        -CPU Usage
        -Memory Usage 
        -Number of threads
    * Output of iostat -x (disk bandwidth statistics) : iostat_yymmdd_hhmmss
    * Disk usage (output of df -k)                    : disk_usage_yymmdd_hhmmss
    * top sample output (top -b -n 2)                 : topout_yymmdd_hhmmss
    * Process wait state (ps -emo pid,ppid,cmd,wchan) : wchan_yymmdd_hhmmss
    * Netstat output (netstat -anpt) for media card   : netstat_yymmdd_hhmmss
    * Netstat output (netstat -anp) for other than media card   : netstat_yymmdd_hhmmss

 The timestamp in the file-name is the time at which the file was
 opened. Samples are added every sampling interval. The sampling interval
 is configurable.

 At the end of a rotation interval, all current files are archived and
 gzipped into a file with name reports_yymmdd_hhmmss.tgz. The time-stamp
 shows the time at which the files were archived.

 To analyze reports after a crash, copy the reports_...tgz files at around
 the time of the crash along with any of the individual files that could
 not be tarred up due to the crash. Use the time-stamp suffixes to identify
 files generated at around the time of the incident. 
 
 Use sysreport.py to generate plots.
"""

import sys
import os
import commands
import time
import os.path
import re
from collections import OrderedDict
import traceback
from datetime import datetime
import calendar
import requests,json

sys.path.append('/DG/activeRelease/rtxlib/pytten')
sys.path.append('/DG/activeRelease/lib/pytten')
sys.path.append('/DG/activeRelease/lib/python_lib')

from Rsyslog import *
from Alarms import *
from log import *
import pyttenremote
import crython
import PGDBMgr

##############################################
# CUSTOMIZABLE PARAMETERS
##############################################

# The following parameters can be modified to alter the
# behaviour of this script. In additions to the parameters
# in this section, you can also modify the monitored_data
# map at the end of the script to add new parameters that
# need to be monitored periodically.

# This script has to periodically obtain a list of process IDs
# that belong to a given process. This is a CPU intensive task.
# If you want accurate per process statistics, set this to 1 so
# that the script gets a PID listing at every sampling.
# If the processes being monitored are long lived and do not
# spawn new threads often, use a higher value like 10 so that
# the script updates the PIDs once in every 10 samplings.
update_samples = 1
# Log rotation interval in seconds. Default - 3600s = 1 hour
rotate_interval = 3600 
# Number of days for which log files have to be retained.
# The script will delete older log files to conserve disk space.
retain_days = 5
# Default sampling interval for process related snapshot - 120 seconds = 2 minutes
Process_poll_interval = 120
# Default sampling interval for system related snapshot -- 240 seconds = 4 minutes
System_poll_interval = 240
# Default sampling interval for Peg related snapshot -- 30 seconds
Peg_poll_interval = 30
# Default sampling interval for View Query related snapshot -- 60 seconds
ViewQry_poll_interval = 60
# Default sampling interval for each postgres DSN Query related snapshot -- 900 seconds
Postgres_poll_interval = 900
# Measuring per process statistics can be CPU intensive.
# To avoid usage spikes, we stagger the process measurements
# so that the load is uniformly distributed. The default
# is to measure process parameters staggered by 2 seconds
# per process group.
stagger_delay = 2
# Set this to 0 to disable per process statistics.
process_monitoring = 1
# CPU Limit For which Thread Dump can be taken.
CPULimitForThresholdDump = 70
#Flag to specify to take Thread Dump
ThreadDumpFlag = 0
# Default location for the monitor logs
monitor_log_directory = "/DGlogs/sysMonitorSnapshot"
EMSConn=''
PGSQLConn=0
ConsulKV = 1
cur = ''

timeout_val=5
UTC_Start_time=0
UTC_End_time=0
MicrosvcsPegPropertyFileFlag=0
MicrosvcsPegDataUpdateFlag=0
Knpegformatter=''
SyncGateway_Json_out = ''
SyncGatewayRep_Json_out=''
SyncGatewayRep_restout_Status = 1
WebAlarm_Url=''
WebAlarmUrlResolveFlag=0
GridGain_Url=''
Grid_SvcPlaneIP_ResolveFlag=0
SyncGateway_restout_Status = 1
SGStats_List_Dicts = []
SGRepStats_List_Dicts = []
CBStats_List_Dicts=[]
DockerPegObjsHash={}
PostGresConnHash={}
Data_Dict_Merge={}
json_out={}
SyncGWREP_PegParams = ['docs_read','docs_written','doc_write_failures']

Service_Type = os.environ.get("SERVICETYPE")
Service_Version = os.environ.get("SERVICEVER")
Signalling_card_name = os.environ.get("SIGNALINGCARDNAME")
Ptt_Server_ID = os.environ.get("PTTSERVERID")
Signalling_card_ID = os.environ.get("SIGNALINGCARDID")
Local_NodeIP_address = os.environ.get("LOCAL_IP_ADDRESS")

RTXType = commands.getoutput("grep RTXTYPE /etc/kodiakDG.conf | cut -d '=' -f2").strip()

if Service_Type == 'RMQ':
    sys.path.append('/DG/activeRelease/Tools/RMQ-scripts/')
    import rabbitmqpegs

# The names of processes for which process-specific monitoring
# is to be done. We will have CPU, memory and thread data for
# these processes.
process_sets = {
    'rtx':[
        'java',
        'python2.7',
        'self',
        'proc(consul-template)',
        'rsyslogd',
        'dnsmasq',
        'snmpd',
        'proc(consul)'
        ]
    }

PegIDMap = {
           12503:{'Name':'DockerSysCPU',
                  'OM_Name':'ContainerCPUUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':75,
                  'LowWaterMark':60,
                  'AlarmCode':8001,
                  'Severity':3
                 },
           33232:{'Name':'SGWR_NUM_PENDING_DOC_FOR_REPLICATION',
                  'OM_Name':'SGWR_NUM_PENDING_DOC_FOR_REPLICATION',
                  'MO_Instance':'SYNCGW',
                  'OM_Type':5,
                  'Threshold':1,
                  'HighWaterMark':15000,
                  'LowWaterMark':10000,
                  'AlarmCode':21306,
                  'Severity':3
                 },
           12502:{'Name':'DockerSysTotalMemUsed',
                  'OM_Name':'ContainerMemoryUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':85,
                  'LowWaterMark':60,
                  'AlarmCode':8002,
                  'Severity':3
                 },
           12515:{'Name':'ContainerMemoryRSSUsage',
                  'OM_Name':'ContainerMemoryRSSUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':85,
                  'LowWaterMark':60,
                  'AlarmCode':10506,
                  'Severity':3
                 },
           152:{'Name':'DG',
                  'OM_Name':'RTXDiskDGUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':80,
                  'LowWaterMark':50,
                  'AlarmCode':8003,
                  'ConsulKVPost':0,
                  'Severity':1
                 },
           150:{'Name':'RTXMemoryUsage',
                  'OM_Name':'RTXMemoryUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':85,
                  'LowWaterMark':60,
                  'AlarmCode':8002,
                  'Severity':3
                 },
           153:{'Name':'DGlogs',
                  'OM_Name':'RTXDiskDGlogsUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':80,
                  'LowWaterMark':50,
                  'AlarmCode':8003,
                  'Severity':1
                 },
           154:{'Name':'var',
                  'OM_Name':'RTXDiskvarUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':80,
                  'LowWaterMark':50,
                  'AlarmCode':8003,
                  'Severity':1
                 },
           155:{'Name':'RTXMemoryUsageWithoutSwap',
                  'OM_Name':'RTXMemoryUsageWithoutSwap',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':85,
                  'LowWaterMark':60,
                  'AlarmCode':8006,
                  'Severity':3
                 },
           165:{'Name':'DGdata',
                  'OM_Name':'RTXDiskDGdataUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':80,
                  'LowWaterMark':50,
                  'AlarmCode':8003,
                  'Severity':1
                 },
           166:{'Name':'Database',
                  'OM_Name':'RTXDiskDatabaseUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':80,
                  'LowWaterMark':50,
                  'AlarmCode':8003,
                  'Severity':1
                 },
           171:{'Name':'RTXSwapMemoryUsage',
                  'OM_Name':'RTXSwapMemoryUsage',
                  'MO_Instance':'Platform',
                  'OM_Type':4,
                  'Threshold':1,
                  'HighWaterMark':50,
                  'LowWaterMark':25,
                  'AlarmCode':10505,
                  'Severity':2
                 },
           35077:{'Name':'CouchData',
                  'OM_Name':'DISK_USAGE_PARTITION_COUCHDATA',
                  'MO_Instance':'CBS',
                  'OM_Type':4,
                  'Threshold':0,
                  'HighWaterMark':80,
                  'LowWaterMark':60,
                  'AlarmCode':21201,
                  'Severity':3
                 },
           35078:{'Name':'CouchIndex',
                  'OM_Name':'DISK_USAGE_PARTITION_COUCHINDEX',
                  'MO_Instance':'CBS',
                  'OM_Type':4,
                  'Threshold':0,
                  'HighWaterMark':80,
                  'LowWaterMark':60,
                  'AlarmCode':21201,
                  'Severity':3
                 },
           38001:{'Name':'PostGresData',
                  'OM_Name':'DISK_USAGE_PARTITION_POSTGRESDATA',
                  'MO_Instance':'PostgreSQL',
                  'OM_Type':4,
                  'Threshold':0,
                  'HighWaterMark':80,
                  'LowWaterMark':60,
                  'AlarmCode':22152,
                  'Severity':3
                 },
           38002:{'Name':'PostGresDataBackup',
                  'OM_Name':'DISK_USAGE_PARTITION_POSTGRESBACKUPS',
                  'MO_Instance':'PostgreSQL',
                  'OM_Type':4,
                  'Threshold':0,
                  'HighWaterMark':80,
                  'LowWaterMark':60,
                  'AlarmCode':22153,
                  'Severity':3
                 }
           }

# The script depends on process counters to determine the
# CPU usage. The kernel reports two types of CPU times
# per thread/process -
# * The CPU time used by the thread/process
# * The CPU time used by all threads/processes spawned by it
# The time used by a spawned process is added to the parent
# only when it exits. In this script, we normally consider
# this time also. This increases the accurace of the CPU
# usage if the process spawns sub-tasks to complete small
# jobs. This can create problems however if the threads spawned
# execute for a couple of minutes and then terminate. In that
# case, CPU usage of the parent thread will show an abnormal
# spike in usage when the thread terminates and skew the
# usage calculations. This happens often with EMS processes.
# For monitoring EMS like processes this option should be set
# to 0.
add_child_data = 1

RTX = ''
DOCID = ''
ReleaseVal = 6

##############################################
# CUSTOMIZABLE PARAMETERS - END
##############################################

custom_parameter = ['update_samples','rotate_interval','retain_days','Process_poll_interval','stagger_delay','process_monitoring','monitor_log_directory','add_child_data','RTX','Peg_poll_interval','System_poll_interval','CPULimitForThresholdDump','ThreadDumpFlag','ViewQry_poll_interval','Postgres_poll_interval']

for keyparam in custom_parameter:
    string = keyparam
    if os.path.isfile('/DG/activeRelease/Tools/Fieldutils/customized_sysmonitor_parameter'):
       vars()[string] = commands.getoutput("grep -w "+keyparam+" /DG/activeRelease/Tools/Fieldutils/customized_sysmonitor_parameter 2>>/dev/null |grep -v '#' |cut -f2 -d '=' 2>>/dev/null").strip()

###################################################################
# READING CUSTOMIZABLE MICROSVCS PARAMETERS FROM MicrosvcsDatFile
###################################################################

custom_parameter = ['Syslog_Kpi_Tag','Kpi_prefix','Rsyslog_host','Rsyslog_port','Syslog_src_port','Kpi_log_path','DBAlarm_Flag','storageTotals_ram','storageTotals_hdd','mainnode','mainnode_buckets','nodes_systemStats','nodes_interestingStats','nodes','PropertyFilePath','WebAlarm_Fqdn','WebAlarm_generate_url','syncgateway_stats','CBS_PegIDS_Params','SG_PegIDS_Params','SGREP_PegIDS_Params','RMQ_PegIDS_Params','GridGain_PegIDS_Params','CBS_Json_all_out','syncGateway_changeCache','syncGateway_db','syncGateway_rest','syncGateway_stats','CBS_CBstats_cmd_lines','Sync_Gateway_Rest_Apis','Sync_Gateway_Rep_Rest_Apis','Grid_Gain_RestApi_Uri']

for keyparam in custom_parameter:
    string = keyparam
    if os.path.isfile('/DG/activeRelease/Tools/Fieldutils/MicrosvcsDatFile'):
               vars()[string] = commands.getoutput("grep -w "+keyparam+" /DG/activeRelease/Tools/Fieldutils/MicrosvcsDatFile 2>>/dev/null |grep -v '#' |cut -f2 -d '=' 2>>/dev/null").strip()

update_samples  = int(update_samples)
rotate_interval = int(rotate_interval)
retain_days     = int(retain_days)
Process_poll_interval   = int(Process_poll_interval)
System_poll_interval   = int(System_poll_interval)
Peg_poll_interval = int(Peg_poll_interval)
ViewQry_poll_interval = int(ViewQry_poll_interval)
Postgres_poll_interval = int(Postgres_poll_interval)
stagger_delay   = int(stagger_delay)
process_monitoring = int(process_monitoring)
add_child_data = int(add_child_data)
CPULimitForThresholdDump = int(CPULimitForThresholdDump)
ThreadDumpFlag = int(ThreadDumpFlag)
DBAlarm_Flag = int(DBAlarm_Flag)
Rsyslog_port = int(Rsyslog_port)
Syslog_src_port = int(Syslog_src_port)

ReleaseValTemp=commands.getoutput("cat /etc/redhat-release 2>>/dev/null| grep [7].[0-9]").strip()
if ReleaseValTemp != '':
   ReleaseVal = 7

if RTX != '':
    RTX = RTX.split(',')   
    for x in RTX: 
       process_sets["rtx"].append(x)

process_sets["rtx"] = set(process_sets["rtx"])
process_sets["rtx"] = list(process_sets["rtx"])

if ReleaseVal == 7:
   DOCID = commands.getoutput('cat /proc/self/cgroup 2>>/dev/null | grep -o -e "docker-.*.scope" | head -n 1 | sed "s/docker-\(.*\).scope/\\1/"')

if Service_Type == 'CBS':
   process_sets["rtx"].append('epmd -daemon')
   process_sets["rtx"].append('proc(memcached)')
   process_sets["rtx"].append('children(beam.smp)')
      
if Service_Type == 'SYNCGW':   
   process_sets["rtx"].append('sync_gateway')
   process_sets["rtx"].append('children(tomcat_instance1.+catalina.sh)')
   process_sets["rtx"].append('children(startup_AMS.sh)')

if Service_Type == 'SYNCGWREP':   
   process_sets["rtx"].append('sync_gateway')

if Service_Type == 'SGACCLRTOR':
   process_sets["rtx"].append('sg_accel')

if Service_Type == 'EXDMS':   
   process_sets["rtx"].append('proc(EXDMS)')

if Service_Type == 'EPRS':   
   process_sets["rtx"].append('proc(EPRS)')

if Service_Type == 'PTMSG':   
   process_sets["rtx"].append('proc(PTMSG)')

if Service_Type == 'EGLS':   
   process_sets["rtx"].append('proc(EGLS)')

if Service_Type == 'KPNS':   
   process_sets["rtx"].append('proc(KPNS)')

if Service_Type == 'ABDG':   
   process_sets["rtx"].append('proc(ABDG)')

if Service_Type == 'RMQ':   
   process_sets["rtx"].append('children(beam.smp)')
   process_sets["rtx"].append('epmd')
   PegIDMap[166]['ConsulKVPost'] = 0

if Service_Type == 'GRIDGAIN':   
   process_sets["rtx"].append('children(java.*GridGainService)')

if int(RTXType) == 4:   
   process_sets["rtx"].append('pocMediaMgr')
   process_sets["rtx"].append('pocTURNServer')

if Service_Type == 'IDAPHadoop':
   process_sets["rtx"].append('proc(proc_namenode)')
   process_sets["rtx"].append('proc(proc_datanode)')
   process_sets["rtx"].append('proc(proc_resourcemanager)')
   process_sets["rtx"].append('proc(proc_nodemanager)')
   process_sets["rtx"].append('proc(HiveMetaStore)')
   process_sets["rtx"].append('proc(statestored)')
   process_sets["rtx"].append('proc(catalogd)')
   process_sets["rtx"].append('proc(impalad)')
   process_sets["rtx"].append('proc(idapsyslog)')
   process_sets["rtx"].append('proc(proc_portmap)')
   process_sets["rtx"].append('proc(proc_nfs3)')
   process_sets["rtx"].append('proc(collectd)')
   process_sets["rtx"].append('proc(proc_historyserver)')

if Service_Type == 'PostgreSQL':
   process_sets["rtx"].append('proc(postgres)')
   process_sets["rtx"].append('proc(collectd)')
   process_sets["rtx"].append('proc(postgres: checkpointer)')
   process_sets["rtx"].append('proc(postgres: writer)')
   process_sets["rtx"].append('proc(postgres: wal writer)')
   process_sets["rtx"].append('proc(postgres: autovacuum launcher)')
   process_sets["rtx"].append('proc(postgres: stats collector)')
   process_sets["rtx"].append('proc(postgres: bgworker: bdr \()')

if Service_Type == 'IDAPElasticsrch':
   process_sets["rtx"].append('proc(tdagent)')
   process_sets["rtx"].append('proc(elasticsearch)')
   process_sets["rtx"].append('proc(collectd)')

if Service_Type == 'IDAPWebService':
   process_sets["rtx"].append('proc(uwsgi)')
   process_sets["rtx"].append('proc(graphite)')
   process_sets["rtx"].append('proc(tomcat)')
   process_sets["rtx"].append('proc(rundeck)')
   process_sets["rtx"].append('proc(collectd)')
   process_sets["rtx"].append('pidfile(/DG/activeRelease/IDAP/tmp/pid/pegevent.pid)')
   process_sets["rtx"].append('pidfile(/DG/activeRelease/IDAP/tmp/pid/peghandle.pid)')

if Service_Type == 'IDAPDshboard':
   process_sets["rtx"].append('proc(grafana-server)')
   process_sets["rtx"].append('proc(kibana)')
   process_sets["rtx"].append('proc(collectd)')
   process_sets["rtx"].append('proc(idashlauncher)')
   process_sets["rtx"].append('proc(grunt)')
   process_sets["rtx"].append('proc(nginx)')

#to write sysmonitor information to respective log file,to avoid writing into log file if disk is full
def printlog(logfilename,logvalue):
    try:
        print >> log_manager.log_fd(logfilename),logvalue
        log_manager.log_fd(logfilename).flush() 
    except:
        pass 

def PostGresDBExecute(query,ConnHand):
    Status,Output,msg = ConnHand.PGFetchDataQry(query)
    if Status == -1:
       printlog('errors',"Failed query"+query+" pgsql "+msg+"")
       PGSQLConn = -1
       ConnHand.PGRetryCount(3)
       Status,msg = ConnHand.PGReconnect()
       if Status == -1:
          printlog('errors',"Failed connect to pgsql "+msg+"")
          PGSQLConn = -1
          return PGSQLConn,Output
       else:
          PGSQLConn = 0
          Status,Output,msg = ConnHand.PGFetchDataQry(query)
          if Status == -1:
             printlog('errors',"Failed query"+query+" pgsql "+msg+"")
             PGSQLConn = -1
             return PGSQLConn,Output
    else:
       PGSQLConn = 0
    
    return 0,Output

def GetPostGresConnection(DBName):
    Status,msg = DBName.PGConnect()
    if Status == -1:
       printlog('errors',"Failed connect to pgsql "+msg+"")
       PGSQLConn = -1 

def getconnection(dsn,IP,UID,PWD,Port):
    try:
        dsn = 'TTC_Server='+str(IP)+';TTC_Server_DSN='+str(dsn)+';uid='+str(UID)+';pwd='+str(PWD)+';tcp_port='+str(Port)+''
        connection = pyttenremote.connect(dsn)
        return connection
    except pyttenremote.DatabaseError, detail:
        Time = datetime.now().strftime("%F %H:%M:%S.%f")
        printlog('errors',"Connect detail: Database connection failed with %s at %s"  % (detail,Time))
        return -1

def DBExecute(query,Flag):
    try:
        cur.execute(query)
        return cur.fetchall()
    except pyttenremote.DatabaseError, detail:
        if Flag == 1:
           matchObj = re.match( r'.*(Unable\s*to\s*connect\s*to\s*daemon|Replication\s*log\s*threshold\s*limit\s*reached\s*at\s*master|Connect\s*failed\s*because\s*max\s*number\s*of\s*connections\s*exceeded|Database\s*Connection\s*is\s*Invalid|799|8025|702|08S01).*', str(detail), re.M)
           if not matchObj:
              return -1

           GetActiveEMSConn()
           if EMSConn == -1:
              Time = datetime.now().strftime("%F %H:%M:%S.%f")
              printlog('errors',"Active EMS IP not found at %s"  % Time)
              return -1
           Status = DBExecute(query,0)
           return Status
        else:
           Time = datetime.now().strftime("%F %H:%M:%S.%f")
           printlog('errors',"DB Fetch Failed %s at %s"  % (detail,Time))
           return -1

def disconnectDB(Conn):
    Conn.disconnect()

class LogManager:
    "A log-file allocator that allocates file-names and manages "
    "log rotation."

    def __init__(self):
        self.file_map = {}
        os.system('mkdir perfreports 2>/dev/null')

    def log_fd(self,name):
        "Returns a file object give a log-name. Log-name can be "
        "a word like 'topdata' in which case a file of the form "
        "topdata_yymmdd_hhmmss is returned."
        if self.file_map.has_key(name):
            return self.file_map[name]
        else:
            fd = open(self.get_log_name(name),'w')
            self.file_map[name] = fd
            return fd

    def get_log_name(self,name):
        return 'perfreports/'+name+time.strftime("_%y%m%d_%H%M%S")

    def rotate(self):
        "Called to close the current logs. Returns a list of "
        "names of the closed log files. Also deletes files from "
        "the perfreports directory that are older than retain-period."
        files_closed = []
        for file in self.file_map.values():
            files_closed.append(file.name)
            try:
                file.close()
            except:
                pass
        self.file_map = {}
        # Remove files older than retain-period
        os.system('rm `find perfreports/ -mtime +%d 2>/dev/null` 2>/dev/null'\
            % retain_days)
        return files_closed

def get_children(pname, shell_script=1):
    "This function is used to track processes that have been spawned "
    "from a shell script. It can also be used to track all child processes "
    "of a given pid (if shell_script is 0, pname is assumed to be a PID file). "
    "A list of PIDs of children, grandchildren, great-grandchildren, ... is "
    "returned. Note that the list contains PIDs are strings."
    track_pid = None
    if shell_script:
        a=1 
    else:
        # Get the PID of the process to be tracked from file.
        try:
            track_pid = open(pname).readline().strip()
        except:
            return []
    # Get all process IDs along with their parent process IDs
    # and file-names.
    out = commands.getoutput('ps -emo pid,ppid,cmd 2>>/dev/null')
    out = out.split('\n')[1:]
    # out is now a list of 'pid, ppid, fname'
    # Construct graph of processes
    # pid_map will have process-ID as the key. The value will
    # be a list of the key's child process-IDs.
    matchObj = re.match( r'.*beam.*smp.*', pname, re.M)
    if matchObj and Service_Type == 'CBS':
        pname=""+pname+".*pidfile"

    pid_map = {}
    for line in out:
        lsplit = line.split()
        # Get the PID, PPID and command name
        # from the ps listing
        pid,ppid,cmd = lsplit[0:3]
        if shell_script:
            if re.search(pname,line):
                # Get the PID of the shell script.
                # This is the PID we need to track.
                track_pid = pid
        # Populate the PID map. Each PID key will have a list
        # of its children as the value.
        if pid_map.has_key(ppid):
            pid_map[ppid].append(pid)
        else:
            pid_map[ppid] = [pid]
    if not track_pid:
        # We could not locate the process we were supposed to
        # track.
        return []
    # Now that we have a graph that maps a PID to it's 
    # immediate descendants, we need to get all of the tracked PIDs
    # children, grand-children and so on.
    pid_list = []
    def process_node(pid):
        'Function to recursively track down all descendants of a PID'
        pid_list.append(pid)
        if pid_map.has_key(pid):
            for child_pid in pid_map[pid]:
                process_node(child_pid)
    # Call the private function to populate pid_list
    process_node(track_pid)
    # We are done!
    return pid_list

class ThreadData:
    "Contains data pertaining to a single thread. The last recorded "\
    "CPU usage percentage, recording time and last recorded CPU time "\
    "are stored."

    def __init__(self,num_processors):
        self.num_processors = num_processors
        self.count_total = 0
        self.last_record_time = 0
        self.percentage = 0
        self.thread_count = 0
        
    def update(self,reading_time,procline):
        "Updates the thread's usage values using the supplied reading-time "\
        "and line from the thread's stat file."

        # Fields 14,15,16 and 17 contain the CPU usage times.
        if add_child_data:
            time_data = [int(x) for x in procline[13:17]]
        else:
            time_data = [int(x) for x in procline[13:15]]

        self.thread_count = int(procline[19])

        total = 0
        for val in time_data:
            total += val
        if self.last_record_time == 0:
            # First reading - usage percentage cannot be calculated now.
            self.last_record_time = reading_time
            self.count_total = total
        elif reading_time != self.last_record_time:
            # Get the time difference in the recording interval and calculate
            # the thread's CPU usage percentage.
            diff = total - self.count_total
            if diff < 0:
               diff = 0 
            self.percentage = diff/(reading_time - self.last_record_time)/\
                self.num_processors
            # Store the new total and the reading for the next calculation.
            self.last_record_time = reading_time
            self.count_total = total

class ProcessData:
    "Maintains data for an entire process (all threads of the process)."

    def __init__(self,num_processors,name,procps_patched):
        self.num_processors = num_processors
        self.name = name
        self.procps_patched = procps_patched
        # Map of the thread PID and it's ThreadData structure
        self.thread_data = {}
        self.main_thread_id = None
        # Process VM size and RSS
        self.vmsize = 0
        self.rss = 0
        self.psmap = 0
        self.private_writable_mem = 0
        self.reading_time = 0
        self.total_percentage = 0
        self.threadscount = 0
        self.FDCount = 0
        # Stores the number of CPU usage updates done for the process.
        # Used to trigger periodic PID updates for the process.
        self.updates = 0
        # Get all PIDs of the threads of this process and create the
        # thread-data structures for them
        self.update_pids()

    def update_pids(self):
        "Gets the PIDs of the threads belonging to the process. Creates "\
        "thread-data structures for tracking new threads. Deletes tracking "\
        "structures for threads that have died."
        # Use pgrep to get the PIDs of the threads. More efficient than
        # scanning the entire procfs files ourselves.
        if self.name == 'self':
            pids = [os.getpid()]
        elif self.name.find('children(') != -1:
            # Extract the name of the shell script
            shell_script_name = self.name.split('(')[1][:-1]
            # Get all children, grandchildren, ...
            pids = get_children(shell_script_name)
          
            try:
                pids = [int(x) for x in pids]
            except:
                pids = []
        elif self.name.find('pidfile(') != -1:
            pid_file_name = self.name.split('(')[1][:-1]
            pids = get_children(pid_file_name, 0)
            try:
                pids = [int(x) for x in pids]
            except:
                pids = []
	elif self.name.find('proc(') != -1:
	    pid_file_name = self.name.split('(')[1][:-1]
	    try:
	        pids = [int(x) for x in\
		    commands.getoutput("ps -ef 2>>/dev/null | grep "+pid_file_name+" | grep -v grep | awk '{print $2}'").split()]
	    except:
		pids = []
        else:
                pids = [int(x) for x in \
                    commands.getoutput("pgrep %s 2>>/dev/null" % (self.name[0:15])).split()]
        if len(pids) == 0:
             printlog('errors',"Process: %s. No threads found."  % self.name)    
             self.main_thread_id = -1
        else:
            if add_child_data:
                # Use the last thread-ID in the list for mapping the
                # the memory usage of the process. This is done since
                # many RTX processes have a dummy outer process to
                # communicate with the platform.
                self.main_thread_id = pids[-1]
            else:
                # In this mode we are monitoring a process that has
                # many short-lived threads. It's better to use one
                # of the IDs at the beginning for getting memory usage.
                if len(pids) > 1:
                    self.main_thread_id = pids[1]
                else:
                    self.main_thread_id = pids[0]
        existing_threads = self.thread_data.keys()[:]
        # Find threads which have died and remove their thread_data entries
        for thread_id in existing_threads:
            if pids.count(thread_id) == 0:
                try:
                    del self.thread_data[thread_id]
                    del self._thread_data[thread_id]
                except:
                    pass
        # Create ThreadData for new PIDs (PIDs that don't have a thread-data
        # structure in the map)
        for pid in pids:
            if not self.thread_data.has_key(pid):
                self.thread_data[pid] = ThreadData(self.num_processors)

    def update_data(self):
        # Increment the update-count. For every 10 updates, check if there
        # are any changes in the PIDs of the threads belonging to the process.
        self.reading_time = time.time()
        lthreads = 0
        total_percentage = 0
        self.updates += 1
        if self.updates % update_samples == 0:
            self.update_pids()
        if self.main_thread_id == -1:
            self.total_percentage = 0
            self.private_writable_mem = 0
            self.rss = 0
            self.psmap = 0
            self.vmsize = 0
            self.FDCount = 0
            self.threadscount = 0
            self.updates = 0
            return
        # Update the thread data
        for pid in self.thread_data.keys():
            # For each thread belonging to the process, read the
            # procfs stats for the thread and pass the data to the
            # thread-data class to update the thread's usage data.
            try:
                f = open('/proc/%d/stat' % pid)
                times = f.readline().split()
            except:
                continue
            self.thread_data[pid].update(self.reading_time,times)
            total_percentage += self.thread_data[pid].percentage

            lthreads += self.thread_data[pid].thread_count
        self.total_percentage = total_percentage
        self.threadscount=lthreads
	
        # Get the private writable memory available to the process.
        # This will be a better indication of the memory used by the 
        # process rather than the RSS or Size values in the proc file-system
        matchObj = re.match( r'.*children\(.*', self.name, re.M)
        if matchObj:
           self.private_writable_mem = 0
           for pid in self.thread_data.keys():
               pvtmemperpid = commands.getoutput\
                   ("(pmap -d %d 2>/dev/null || pmap %d 2>/dev/null) "\
                   "| egrep 'writ[e]?able/private' "\
                   "| awk -Fate: '{print $2}' | awk -FK '{print $1}'" %\
                   (pid,pid))
               try:
                  pvtmemperpid = int(pvtmemperpid)
               except:
                  pvtmemperpid = 0
               self.private_writable_mem = self.private_writable_mem + pvtmemperpid
        else:
           self.private_writable_mem = commands.getoutput\
               ("(pmap -d %d 2>/dev/null || pmap %d 2>/dev/null) "\
               "| egrep 'writ[e]?able/private' "\
               "| awk -Fate: '{print $2}' | awk -FK '{print $1}'" %\
               (self.main_thread_id, self.main_thread_id))
        try:
            self.private_writable_mem = int(self.private_writable_mem)
        except:
             printlog('errors',"Main thread (ID:%d) of process %s appears to have died." %  (self.main_thread_id, self.name))
             self.private_writable_mem = -1
        # Get the VmSize and VmRSS values
        try:
            # Get this from the status file of the last thread belonging
            # to the process. The memory usage figures need not be added
            # up. They will be same for all the threads.
            self.vmsize = 0
            self.rss = 0
            self.psmap = 0
            self.FDCount = 0
            matchObj = re.match( r'.*children\(.*', self.name, re.M)
            if matchObj:
               pidarray = self.thread_data.keys()
            else:
               pidarray = [ self.main_thread_id ]

            for pid in pidarray:
               self.FDCountTemp = commands.getoutput('ls -l /proc/%s/fd 2>>/dev/null | wc -l' % pid)
               self.FDCountTemp = int(self.FDCountTemp)
               self.FDCount = self.FDCountTemp + self.FDCount
               
               if ReleaseVal == 7:
                  self.psmapTemp = commands.getoutput('python /DG/activeRelease/Tools/Fieldutils/ProcessMem.py -p %s 2>>/dev/null' % pid)
                  if not self.psmapTemp:
                     self.psmapTemp = 0
                  self.psmapTemp = int(self.psmapTemp)
                  self.psmap = self.psmapTemp + self.psmap

               f = open('/proc/%d/status' % pid)
               lines = f.readlines()
               for line in lines:
                   if line.find('VmSize')==0:
                       count,unit = line.split(':')[1].split()
                       count = int(count)
                       unit = unit.strip()
                       if unit == 'kB':
                          count *= 1000
                       vmsizeperpid = count/1000
                       self.vmsize = self.vmsize + vmsizeperpid
                   if line.find('VmRSS')==0:
                       count,unit = line.split(':')[1].split()
                       count = int(count)
                       unit = unit.strip()
                       if unit == 'kB':
                          count *= 1000
                       rsssizeperpid = count/1000
                       self.rss = self.rss + rsssizeperpid
        except:
            pass

    def get_stats(self):
        "Returns a printable line containing the reading time, process name, "\
        "memory statistics, overall CPU usage and the CPU usage breakup for "
        "the threads belonging to the process."
        # Compose the process level statistics.
        length = len(self.thread_data)
        if length > 1: 
          length = length - 1
        retstr = 'time:%f, name:%s, pvt-wr-mem: %d kB, cpu: %.3f, '\
            'rss: %d kB, vmsize: %d kB, threads: %d, ctime: %s, fdcount: %d' % \
            (self.reading_time,self.name,self.private_writable_mem,\
            self.total_percentage, self.rss, self.vmsize,
            self.threadscount, time.ctime(self.reading_time),self.FDCount)
        return retstr

    def get_psmemstats(self):
        return ""+time.strftime("%Y/%m/%d %H:%M:%S")+" "+self.name+" "+str(self.psmap)+" kB"

    def GetThreadHeapDump(self):
        "Get heap Dump and Thread Dump for Java Related process."
        JavaHome=os.environ.get("JAVAHOME32")
        matchObj = re.match( r'.*(tomcat_instance1).*', self.name, re.M)
        if matchObj and self.total_percentage > CPULimitForThresholdDump and ThreadDumpFlag == 1:
            printlog('ThreadDump',commands.getoutput("/DG/activeRelease/Tools/Fieldutils/ThreadDumpSnapshot.sh '"+self.name+"'"))

class ProcReader:
    "Contains a collection of processes being monitored for CPU and "\
    "memory usage."

    def __init__(self,num_processors,process_names,procps_patched):
        self.num_processors = num_processors
        self.process_names = [x for x in process_names if x[0] != '-']
        # Create the process data collecting class instance for each process
        self.processes = {}
        for process_name in self.process_names:
            self.processes[process_name] = ProcessData(self.num_processors,\
                process_name,procps_patched)
        self.current_process = 0
        self.num_processes = len(self.process_names)

    def update_data(self):
        "Updates statistics for each process and prints a line containing the "\
        "current data."
        process_data = self.processes.values()[self.current_process]
        process_data.update_data()
        printlog('processinfo',process_data.get_stats())    
        if ReleaseVal == 7:
           printlog('psmeminfo',process_data.get_psmemstats())    
        process_data.GetThreadHeapDump()
        
        self.current_process += 1
        if self.current_process == self.num_processes:
            self.current_process = 0
        self.private_writable_mem = 0
        self.total_percentage = 0
        self.rss = 0
        self.psmap = 0
        self.vmsize = 0
        self.threadscount = 0
        self.FDCount = 0
        self.updates = 0

class PegData:
    "Updating peg data into DB"

    def __init__(self,PegID):
       self.Count = 0
       self.ThresholdCount = 0
       self.data = 0
       self.prev = 0
       self.current = 0
       self.Average = 0
       self.Alarm = 0
       self.PegID = PegID
       self.ThresholdEnable = ''
       self.PreviousContainerCPU = 0
       self.PreviousTimeNanoSec = 0
       self.Val = 0
       self.AlarmCount = 0

    def GetContainerCPU(self):
       PegValue = 0
       if self.PegID == 12503:
          TimeNanoSec  = commands.getoutput('date +%s%N')
          ContainerCPU = commands.getoutput("cat /sys/fs/cgroup/cpuacct/system.slice/docker-"+DOCID+".scope/cpuacct.usage 2>>/dev/null")

          CurrentContainerCPU = float(ContainerCPU) - float(self.PreviousContainerCPU)
          CurrentTime = float(TimeNanoSec) - float(self.PreviousTimeNanoSec)

          if CurrentTime == 0:
             return PegValue,PegValue

          PegValue = CurrentContainerCPU / CurrentTime
          PegValue = PegValue * 100

          if processors == 0:
             return PegValue,PegValue

          PegValue = PegValue / processors
          self.PreviousContainerCPU = ContainerCPU
          self.PreviousTimeNanoSec  = TimeNanoSec

       if self.PegID == 'DockerSysIdle':
          PegValue = 100 - DockerPegCPU.Val
       
       return PegValue,PegValue

    def GetMemoryDetails(self):
       PercVal = -1
       PegValue = 0

       if self.PegID == 'DockerSysMemCache':
          PegValue = float(DockerPegContainerTotalMemUsed.MemoryCache) / 1024 / 1024

       if self.PegID == 12515:
          PegValue = float(DockerPegContainerTotalMemUsed.MemoryRSS) / 1024 / 1024

       if self.PegID == 'DockerSysCache':
          PegValue = commands.getoutput("cat /sys/fs/cgroup/memory/system.slice/docker-"+DOCID+".scope/memory.stat 2>>/dev/null | grep -w cache | awk '{ foo = $2 / 1024 / 1024 ; print int(foo) }'")

       if self.PegID == 'DockerSysTotalMem':
          PegValue = commands.getoutput("cat /sys/fs/cgroup/memory/system.slice/docker-"+DOCID+".scope/memory.limit_in_bytes 2>>/dev/null | awk '{ foo = $1 / 1024 / 1024 ; print int(foo) }'")
          PegValue = int(PegValue)

       if self.PegID == 12502:
          self.MemoryCache = 0
          self.MemoryRSS = 0
          self.RSSTotal = 0
          
          MemoryDetArr = commands.getoutput("egrep -w 'rss|cache' /sys/fs/cgroup/memory/system.slice/docker-"+DOCID+".scope/memory.stat | sed -e 's/ /-/g'").split('\n')
          for MemoryStatVal in MemoryDetArr:
             Name = MemoryStatVal.split('-')[0]
             Value = MemoryStatVal.split('-')[1]
    
             if Name == 'cache':
                self.MemoryCache = float(Value)
          
             if Name == 'rss':
                self.MemoryRSS = float(Value)
          
          RSSArr = commands.getoutput("cat /proc/sysvipc/shm | awk -F ' ' '{print $15}' | grep -v 'rss'").split('\n')
          for RSSVal in RSSArr:
             if RSSVal != '':
                self.RSSTotal = int(RSSVal) + int(self.RSSTotal)

          PegValue = (self.MemoryRSS + self.RSSTotal) / 1024 / 1024
          if int(DockerPegContainerTotalMem.Val) != 0 and DockerPegContainerTotalMem.Val != '':
             PercVal = 100 * float(PegValue)/float(DockerPegContainerTotalMem.Val)

       if self.PegID == 'DockerSysTotalFreeMem':
          PegValue = float(DockerPegContainerTotalMem.Val) - float(DockerPegContainerTotalMemUsed.Val)
       
       return PegValue,PercVal

    def GetReplicationLagCnt(self):
       PegValue = 0
       RemoteClusterID = 1

       if self.PegID == 33232:
          if int(os.environ.get("CLUSTERID")) == 1:
             RemoteClusterID = 2 
          PegValue = commands.getoutput("source /DG/activeRelease/Tools/kodiakScripts.conf; python /DG/activeRelease/Tools/CBSRepLagCount.py --lag --fromClusterId "+str(os.environ.get("CLUSTERID"))+" --toClusterId "+str(RemoteClusterID)+" --sysMon")
          if not PegValue:
             PegValue = 0
          return int(PegValue),int(PegValue)
         
    def GetThresholdValueEMS(self):
       if self.PegID not in PegIDMap:
             self.ThresholdEnable = 1
             self.HighWaterMark = 85
             self.LowWaterMark = 60
             self.AlarmCode = 8003
             self.AlarmSeverity = 1
             return
       
       GetThresholdDetailsQry = 'select THRESHOLD_ENABLED,HIGH_WATERMARK,LOW_WATERMARK,ALARMCODE,ALARM_SEVERITY from DG.PERF_PEGCONFIG_'+str(os.environ.get("PTTSERVERID"))+' where PARAMINDEX='+str(self.PegID)+''
       ThresholdDetails = DBExecute(GetThresholdDetailsQry,1)
       if not ThresholdDetails or ThresholdDetails == -1:
          printlog('monitor_log',"No Details found for PEGID %s"  % self.PegID)
          if self.ThresholdEnable == '':
             self.ThresholdEnable = PegIDMap[self.PegID]['Threshold']
             self.HighWaterMark = PegIDMap[self.PegID]['HighWaterMark']
             self.LowWaterMark = PegIDMap[self.PegID]['LowWaterMark']
             self.AlarmCode = PegIDMap[self.PegID]['AlarmCode']
             self.AlarmSeverity = PegIDMap[self.PegID]['Severity']
       else:
          self.ThresholdEnable = ThresholdDetails[0][0]
          self.HighWaterMark = ThresholdDetails[0][1]
          self.LowWaterMark = ThresholdDetails[0][2]
          self.AlarmCode = ThresholdDetails[0][3]
          self.AlarmSeverity = ThresholdDetails[0][4]

    def UpdatePegData(self,value,PercVal,Flag):
       FileName = 'Dockerinfo'
       self.Count = self.Count + 1
       self.data = self.data + float(value)
       Name = self.PegID
       if Name in PegIDMap:
          Name = PegIDMap[self.PegID]['Name']

       CurrentDate = commands.getoutput("date +'%Y/%m/%d %H:%M:%S'")
       LogVal = str(Name) + ',' + str(CurrentDate) + ',' + str(value)
       if self.PegID == 12503 or self.PegID == 'DockerSysIdle':
          LogVal = LogVal + ' %'
       elif self.PegID == 33232:
          FileName = 'ViewQueryInfo'
          self.current = value
       elif Flag == 1:
          FileName = 'PartitionInfo'
          self.current = value 
          LogVal = LogVal + ' %'
       else:
          LogVal = LogVal + ' MB'

       printlog(FileName,LogVal)
       Time = datetime.now().strftime("%F %H:%M:%S.%f")

       try:
          matchObj = re.match( r'^\s*12503|12502|33232|152|153|154|165|166|171|35077|35078|12515|150|155|38001|38002\s*$', str(self.PegID), re.M)
          if matchObj or Flag == 1:
             self.GetThresholdValueEMS()
             if self.ThresholdCount >= 3 and self.AlarmCode != 0 and self.ThresholdEnable == 1:
                self.AlarmSeverity=0
                if float(PercVal) > float(self.LowWaterMark) and float(PercVal) <= float(self.HighWaterMark):
                    self.AlarmSeverity=1
                    # Raise Major alarm(1) if value is between Low water mark and high water mark.
                    # Raise critical alarm(0) if value is >= high water mark.
                    # Raise clear alarm(4) if value is less than low water mark.
                printlog('monitor_log',"Raise Alarm for PegID: %s with HighWaterMark: %s LowWaterMark: %s PercVal: %s at time: %s" % (self.PegID,self.HighWaterMark,self.LowWaterMark,PercVal,Time))
                (json_payload,headers) = GetWebAlarmJsonPayloadPegID(self.AlarmCode,self.AlarmSeverity)
                AlarmStat = Alarm_obj.RaiseWebAlarm(WebAlarm_Url,json_payload,headers)
                self.Alarm = 1
                self.ThresholdCount = 0
                if 'ConsulKVPost' in PegIDMap[self.PegID] and self.AlarmSeverity == 0: 
                   PegIDMap[self.PegID]['ConsulKVPost'] = 1
             elif ((float(PercVal) >= float(self.HighWaterMark)) or (float(PercVal) > float(self.LowWaterMark) and float(PercVal) <= float(self.HighWaterMark)) and self.AlarmCode != 0 and self.ThresholdEnable == 1):
                    self.ThresholdCount = self.ThresholdCount + 1
                    if 'ConsulKVPost' in PegIDMap[self.PegID]:
                        PegIDMap[self.PegID]['ConsulKVPost'] = 0
             elif float(PercVal) <= float(self.LowWaterMark) and self.AlarmCode != 0 and self.ThresholdEnable == 1:
                    if self.Alarm == 1 or self.AlarmCount == 0:
                        printlog('monitor_log',"Clear Alarm for PegID: %s with HighWaterMark: %s LowWaterMark: %s PercVal: %s at time: %s" % (self.PegID,self.HighWaterMark,self.LowWaterMark,PercVal,Time))
                        (json_payload,headers) = GetWebAlarmJsonPayloadPegID(self.AlarmCode,4)
                        AlarmStat = Alarm_obj.RaiseWebAlarm(WebAlarm_Url,json_payload,headers)
                        if AlarmStat == 0:
                            self.Alarm = 0
                            self.AlarmCount = 1
                    self.ThresholdCount = 0   
                    if 'ConsulKVPost' in PegIDMap[self.PegID]: 
                        PegIDMap[self.PegID]['ConsulKVPost'] = 0
       except:
         printlog('errors',"Failed to post Alarm for %s at %s"  % (self.PegID,Time))

    def UpdateMicrosvcs_PegData(self,PegValue,Threshold_Prop_Dict):
       self.Count = self.Count + 1
       diff = abs(int(PegValue) - int(self.prev))
       self.data = self.data + int(diff)
       PegValue = int(PegValue)
       self.current = PegValue
       self.prev = PegValue
       CurrentDate = commands.getoutput("date +'%Y/%m/%d %H:%M:%S'")
       Thresholdenabled = Threshold_Prop_Dict['thresholdenabled']
       Highwatermark = Threshold_Prop_Dict['highwatermark']
       Lowwatermark =  Threshold_Prop_Dict['lowwatermark']
       AlarmCode = Threshold_Prop_Dict['alarmcode']
       AlarmSeverity = Threshold_Prop_Dict['alarmseverity']
       Time = datetime.now().strftime("%F %H:%M:%S.%f")

       try:
         ######################################################################################################################
         if Thresholdenabled == 1 and WebAlarmUrlResolveFlag == 1 and AlarmCode != 0:
           if self.ThresholdCount >= 3:
                AlarmSeverity=0
                if PegValue > Lowwatermark and PegValue <= Highwatermark:
                    AlarmSeverity=1
                    # Raise Major alarm(1) if value is between Low water mark and high water mark.
                    # Raise critical alarm(0) if value is >= high water mark.
                    # Raise clear alarm(4) if value is less than low water mark.
                printlog('monitor_log',"Raise Alarm for PegID[%s],with HighWaterMark[%s],LowWaterMark[%s],PercVal[%s] at time[%s]" % (self.PegID,Highwatermark,Lowwatermark,PegValue,Time))
                (json_payload,headers) = GetWebAlarmJsonPayloadPegID(AlarmCode,AlarmSeverity)
                AlarmStat = Alarm_obj.RaiseWebAlarm(WebAlarm_Url,json_payload,headers)
                self.Alarm = 1
                self.ThresholdCount = 0
           elif PegValue >= Highwatermark or (PegValue > Lowwatermark and PegValue <= Highwatermark):
                    self.ThresholdCount = self.ThresholdCount + 1
           elif PegValue <= Lowwatermark:
                    if self.Alarm == 1 or self.AlarmCount == 0:
                        printlog('monitor_log',"Clear Alarm for PegID[%s],with HighWaterMark[%s],LowWaterMark[%s],PercVal[%s] at time[%s]" % (self.PegID,Highwatermark,Lowwatermark,PegValue,Time))
                        (json_payload,headers) = GetWebAlarmJsonPayloadPegID(AlarmCode,4)
                        AlarmStat = Alarm_obj.RaiseWebAlarm(WebAlarm_Url,json_payload,headers)
                        if AlarmStat == 0:
                            self.Alarm = 0
                            self.AlarmCount = 1
                    self.ThresholdCount = 0 
       
       except:
         printlog('errors',"Failed to post Alarm for %s at %s"  % (self.PegID,Time))
             
    def GetValueOfPeg(self):
       matchObj = re.match( r'.*(DockerSysCache|DockerSysTotalMem|12502|12515|DockerSysTotalFreeMem|DockerSysMemCache).*', str(self.PegID), re.M)
       if matchObj:
          self.Val,PercVal = self.GetMemoryDetails()
          self.UpdatePegData(self.Val,PercVal,0)

       matchObj = re.match( r'.*(12503|DockerSysIdle).*', str(self.PegID), re.M)
       if matchObj:
          self.Val,PercVal = self.GetContainerCPU()
          self.UpdatePegData(self.Val,PercVal,0)

       matchObj = re.match( r'.*33232.*', str(self.PegID), re.M)
       if matchObj:
          self.Val,PercVal = self.GetReplicationLagCnt()
          self.UpdatePegData(self.Val,PercVal,0)

    def GetPartitionUsedVal(self):
       PartitionStr = self.PegID

       if self.PegID in PegIDMap:
          PartitionStr = str(PegIDMap[self.PegID]['Name'])
          if PartitionStr == 'PostGresData' or PartitionStr == 'PostGresDataBackup':
             PartitionStr = 'PostgresData'
       PercVal = commands.getoutput("/bin/df -Ph | egrep '"+str(PartitionStr)+"$' | awk -F' ' '{print $5}' | sed -e 's/%//' 2>>/dev/null")
       if PercVal == '':
          PercVal = 0
       self.UpdatePegData(PercVal,PercVal,1)

    def GetPlatformMemVal(self):
     
       if self.PegID == 171:
          SwapTotal = commands.getoutput("grep SwapTotal /proc/meminfo | awk -F ' *' '{print $2}' 2>>/dev/null")
          SwapFree = commands.getoutput("grep SwapFree /proc/meminfo | awk -F ' *' '{print $2}' 2>>/dev/null")
          SwapUsed = (int(SwapTotal) - int(SwapFree))/1024
          self.UpdatePegData(SwapUsed,SwapUsed,0)
         
       if self.PegID == 150:
          SwapTotal = commands.getoutput("grep SwapTotal /proc/meminfo | awk -F ' *' '{print $2}' 2>>/dev/null")
          MemTotal = commands.getoutput("grep MemTotal /proc/meminfo | awk -F ' *' '{print $2}' 2>>/dev/null")
          MemAvailable = commands.getoutput("grep MemAvailable /proc/meminfo | awk -F ' *' '{print $2}' 2>>/dev/null")
          TotalMem = int(MemTotal)+ int(SwapTotal)
          TotalUsed = TotalMem - int(MemAvailable)
          MemUsedWithSwap = (float(TotalUsed)/float(TotalMem)) * 100;
          self.UpdatePegData(MemUsedWithSwap,MemUsedWithSwap,1)
           
       if self.PegID == 155:
          MemTotal = commands.getoutput("grep MemTotal /proc/meminfo | awk -F ' *' '{print $2}' 2>>/dev/null")
          MemAvailable = commands.getoutput("grep MemAvailable /proc/meminfo | awk -F ' *' '{print $2}' 2>>/dev/null")
          MemUsed = int(MemTotal) - int(MemAvailable)
          MemUsedWithoutSwap = (float(MemUsed)/float(MemTotal)) * 100;
          self.UpdatePegData(MemUsedWithoutSwap,MemUsedWithoutSwap,1)

    def UpdateAvgOfMicrosvcsPeg(self):
       if self.data == '' or self.Count == '' or self.Count == 0:
          Time = datetime.now().strftime("%F %H:%M:%S.%f")
          printlog('errors',"No Avg values found for %s to update at %s"  % (self.PegID,Time))
          return

       PegAvg = float(self.data) / float(self.Count)
       PegAvg = round(PegAvg,3)
       self.Average = PegAvg

def get_cpu_info():
    "Gets the CPU model name and the number of processors on the system. "\
    "Returns (number of processors (int), model string)."
    model_name = ''
    num_processors = 0
    f = open('/proc/cpuinfo')
    lines = f.readlines()
    for line in lines:
        if line.find('model name') == 0:
            model_name = line.split(':')[1].strip()
        elif line.find('processor') == 0:
            num_processors += 1
    return num_processors,model_name

def start_continuous_data_monitoring(monitored_data,flag):
    log_file_names = []
    for data_file in monitored_data.keys():
        if data_file == 'heapinfo':
           os.system('/DG/activeRelease/Tools/Fieldutils/heaprun.sh stop')
        else:
           os.system('pkill -f "%s"' % monitored_data[data_file])
        log_file_name = log_manager.get_log_name(data_file)
        log_file_names.append(log_file_name)
        Actfilename = os.path.basename(log_file_name)
        if flag == 1:
           if data_file == 'heapinfo':
              os.system(monitored_data[data_file]+' %s'%Actfilename)
           else:
              os.system(monitored_data[data_file]+' > %s&'%log_file_name)
    return log_file_names

def get_system_type():
    # Check the type of system we are running on:
    # RTX, EMS
    # If command-line parameters are specified, use them
    retval = ''
    if len(sys.argv) > 1:
        if sys.argv.count('--rtx') != 0:
            retval = 'rtx'

    # Assume RTX if none of the conditions are satisfied.
    if retval == '':
        retval = 'rtx'
    return retval
	
def check_system_configuration():
    processors, model_name = get_cpu_info()
    printlog('monitor_log',model_name)
    
    printlog('monitor_log',"Processors: "+str(processors)+"")
    # Our results also depend on the version of the process
    # monitoring tools on the system.
    procps_version = commands.getoutput('rpm -q procps 2>>/dev/null').strip()
    printlog('monitor_log',procps_version)
    matchObj = re.match( r'procps', procps_version, re.M)
    if matchObj:
        return 0, processors
    else:
        return 1, processors

@crython.job(second=0,minute='*/5')
def SchedulerJob():

    ################################# Sending Docker(Platform) Pegs Data to Rsyslog #######################################
    ################################# Also updated PegIDMap Dict to include info required for KPI pegging ################# 

    UTC_Start_time=Get_UTC_epoch()
    UTC_Start_Time_secs = UTC_Start_time
    UTC_Start_time = str(UTC_Start_Time_secs)
    UTC_End_Time_secs = UTC_Start_Time_secs+300
    UTC_End_time = str(UTC_End_Time_secs) 
    Docker_Threshold_Prop_Dict={}
    for DockerPegID in PegIDMap.keys():
        if DockerPegID == 33232 and Service_Type != 'SYNCGWREP':
           continue
        if (DockerPegID == 35077 or DockerPegID == 35078) and Service_Type != 'CBS':
           continue
        if (DockerPegID == 38001 or DockerPegID == 38002) and Service_Type != 'PostgreSQL':
           continue
        DockerPegObj=DockerPegObjsHash[DockerPegID]
        PegID=int(DockerPegObj.PegID)
        if DockerPegObj.data == '' or DockerPegObj.Count == '' or DockerPegObj.Count == 0:
          Time = datetime.now().strftime("%F %H:%M:%S.%f")
          printlog('errors',"No Avg values found for %s to update in DB at %s"  % (DockerPegObj.PegID,Time))
          continue
        Docker_Threshold_Prop_Dict['omname']=PegIDMap[PegID]['OM_Name']
        Docker_Threshold_Prop_Dict['managementobjectinstance']=PegIDMap[PegID]['MO_Instance']
        Docker_Threshold_Prop_Dict['omtype']=PegIDMap[PegID]['OM_Type']
        Docker_Threshold_Prop_Dict['omid']=PegID
        KPIPegging_Microsvcs(Docker_Threshold_Prop_Dict,DockerPegObj,UTC_Start_time,UTC_End_time,Knpegformatter)
    Docker_Threshold_Prop_Dict = {}
    ################## Getting Average/gauge/Snapshot of specific CBS/SG Pegs parameters ###########
    if (Service_Type == 'CBS' or Service_Type == 'SYNCGW' or Service_Type == 'SYNCGWREP' or Service_Type == 'RMQ' or Service_Type == 'GRIDGAIN'):
        for PegID,MvcsPegObj in MicrosvcsPegObjsHash.items():
            PegID = int(PegID)
            Threshold_Prop_Dict = GetThresholdPropDictPegID(Threshold_Prop_List_Dicts,PegID)
            Ispolled_Flag = int(Threshold_Prop_Dict['ispolled'])
            if Ispolled_Flag == 1 and MicrosvcsPegDataUpdateFlag == 1:
                KPIPegging_Microsvcs(Threshold_Prop_Dict,MvcsPegObj,UTC_Start_time,UTC_End_time,Knpegformatter)
        Threshold_Prop_Dict={}    

def GetActiveEMSConn():
    global EMSConn
    global cur
    EMSIPArr = ('EMSIP','EMSIP_REDUNDANT','EMSIP_GEO_REDUNDANT')
    ActFlag = 0
    EMSConn = -1
    cur = -1

    for Itr in range(1,4):
        for Env in EMSIPArr:
            if Env in os.environ:
                if os.environ.get(Env) != '':
                   EMSConn = getconnection(os.environ.get("EMSDSN"), os.environ.get(Env), os.environ.get("EMSUSERID"), os.environ.get("EMSPASSWORD"), os.environ.get("TT_REMOTE_PORT"))
                   if EMSConn != -1:
                      ActFlag = 1
                      break
        if ActFlag == 1:
           break

    if EMSConn != -1:
        GetActiveEMSDetailsQry = "select DBDATASOURCENAME,IPADDRESS,DBUID,DBPWD,TT_REMOTE_PORT from DG.emsinfo where ISACTIVE ='Y'"
        cur = EMSConn.cursor()
        ActiveEMSDet = DBExecute(GetActiveEMSDetailsQry,1)
        if ActiveEMSDet:
           ActEMSConn = getconnection(ActiveEMSDet[0][0],ActiveEMSDet[0][1],ActiveEMSDet[0][2],ActiveEMSDet[0][3],ActiveEMSDet[0][4])
           if ActEMSConn != -1:
              disconnectDB(EMSConn)
              EMSConn = ActEMSConn
              ActEMSConn = -1
        cur = EMSConn.cursor()

################ CBS/SG/RMQ/GGAIN functions relevent to CBS Rest calls ###########################################################
def GetValueof_RMQ_Peg():
   global Data_Dict_Merge
   global json_out
   global MicrosvcsPegDataUpdateFlag
   RMQ_Data_Dict_Merge={}
   RMQ_Data_Dict={}
   try:
	RMQ_Data_Dict=rabbitmqpegs.main(cur)
        Data_Dict_Merge=RMQ_Data_Dict
        json_out=RMQ_Data_Dict
        MicrosvcsPegDataUpdateFlag=1
   except:
        pass 

def GetMicrosvcs_PegIDParamsOrderedDict(CBS_PegIDS_Params):
    Microsvcs_Params_dict={}
    Microsvcs_Params_dict=OrderedDict()
    if CBS_PegIDS_Params != '':
        CBS_PegIDS_Params_List = CBS_PegIDS_Params.split(',')
        for CBS_PegIDS_Params in CBS_PegIDS_Params_List:
            CBS_PegIDS_Params = CBS_PegIDS_Params.split(':')
            Microsvcs_Params_dict[CBS_PegIDS_Params[0]]=int(CBS_PegIDS_Params[1])
    return Microsvcs_Params_dict

def GetValueof_CBS_Peg():
        global Data_Dict_Merge
        global json_out
        CBS_Data_Dict_Merge = {}
        Microsvcs_Params = Microsvcs_PegIDS_ParamDict.keys()
        CBS_Data_Dict_Merge = GetDefault_SG_Data_Dict_Merge(CBS_Data_Dict_Merge,Microsvcs_Params)
        GetCumulativeCBSJson_Output(CBS_CBstats_cmd_lines)
        CBStats_CumulativeJsonout = Merge_JsonDicts(CBStats_List_Dicts)
        for Microsvcs_Param in Microsvcs_Params:
            if Microsvcs_Param in CBStats_CumulativeJsonout: CBS_Data_Dict_Merge.update({Microsvcs_Param:CBStats_CumulativeJsonout[Microsvcs_Param]}) 
        Data_Dict_Merge=CBS_Data_Dict_Merge
        json_out=CBStats_CumulativeJsonout 

def GetDatafromPropertyFile(CBSPropertyFile):
    try:
        with open(CBSPropertyFile) as f:
            first_line = f.readline()
            for line in f.read().splitlines():
                line=line.rstrip().split('=')
                if line[0].rstrip() == 'ADMIN_USER': CBSUserID=line[1]
                if line[0].rstrip() == 'ADMIN_PASSWORD': CBSPassword=line[1]
    except:
           printlog('errors',"Failure: Cannot read/open CBS property File %s" %(CBSPropertyFile))
    return(CBSUserID,CBSPassword)

def GetCumulativeCBSJson_Output(CBS_CBstats_cmd_lines):
    global CBStats_List_Dicts
    global MicrosvcsPegDataUpdateFlag
    CBStats_List_Dicts=[]
    CBS_CBstats_Cmd_Lines_List = CBS_CBstats_cmd_lines.split(',')
    for CBS_CBstats_Cmd_Line in CBS_CBstats_Cmd_Lines_List:
       try:
            CBS_CBstats_Cmd_Line=CBS_CBstats_Cmd_Line.replace('uid',CBSUserID)
            CBS_CBstats_Cmd_Line=CBS_CBstats_Cmd_Line.replace('password',CBSPassword)
	    (Cmd_Status,CBS_Json_out) = commands.getstatusoutput(CBS_CBstats_Cmd_Line)
            CBS_Json_out = json.loads(CBS_Json_out)
            if Cmd_Status == 0:
                MicrosvcsPegDataUpdateFlag=1
                CBStats_List_Dicts.append(dict(CBS_Json_out))
       except:         
                pass

def Merge_JsonDicts(CBStats_List_Dicts):
    CBStats_CumulativeJsonout={}
    CBStats_CumulativeJsonout = {key:val for d in CBStats_List_Dicts for key,val in d.items()}
    return CBStats_CumulativeJsonout

def GetValueof_GRIDGAIN_Peg():
    global Data_Dict_Merge
    global json_out
    Default_GGain_Dict={}
    GGainDataDict_Merge={}
    GridGainJson_out=""
    session_obj=requests.Session()
    Microsvcs_Params=Microsvcs_PegIDS_ParamDict.keys()
    #### Get default Dict Keys in case Rest API O/P is absent ############################
    Default_GGain_Dict=GetDefault_SG_Data_Dict_Merge(Default_GGain_Dict,Microsvcs_Params)
    ######################################################################################
    GridGainJson_out=Get_GridGain_rest_api_data(GridGain_Url,Microsvcs_Params,session_obj,timeout_val)
    if MicrosvcsPegDataUpdateFlag == 1:
        GridGain_Json_out=GridGainJson_out['response']['metrics']
        for Microsvcs_Param in Microsvcs_Params:
            GGainDataDict_Merge.update({Microsvcs_Param:Default_GGain_Dict[Microsvcs_Param]})
            if Microsvcs_Param in GridGain_Json_out.keys(): GGainDataDict_Merge.update({Microsvcs_Param:GridGain_Json_out[Microsvcs_Param]})
        Data_Dict_Merge=GGainDataDict_Merge
        json_out=GridGainJson_out

def Get_GridGain_rest_api_data(url,Microsvcs_Params,session_obj,timeout_val):
    global MicrosvcsPegDataUpdateFlag
    GridGainJson_out=""
    GridGain_Json_out={}
    try:
        r=session_obj.get(url, timeout=timeout_val)
        GridGain_restout_Status=r.status_code
        if GridGain_restout_Status == 200:
            GridGainJson_out=json.loads(r.text)
            MicrosvcsPegDataUpdateFlag=1
            return GridGainJson_out
    except requests.exceptions.HTTPError:
        printlog('errors',"Error: HTTP Error occured when connecting to %s !!"  %(url))
    except requests.exceptions.InvalidURL:
        printlog('errors',"Error: Valid URL is required when connecting to %s !!"  %(url))
    except requests.exceptions.ConnectionError:
        printlog('errors',"Error: Unable to connect to %s !!"  % (url))
    except requests.exceptions.Timeout:
        printlog('errors',"Error: Timeout occurred to connect to %s !!"  % (url))

def GetValueof_SG_Peg():
        Sync_Gateway_RestAPIList=''
        session_obj = requests.Session()
        Microsvcs_Params = Microsvcs_PegIDS_ParamDict.keys()
        Sync_Gateway_RestAPIList=Sync_Gateway_Rest_Apis
        if Service_Type == 'SYNCGWREP':
            Sync_Gateway_RestAPIList=Sync_Gateway_Rep_Rest_Apis
        GetCumulativeSyncGatewayJson_Output(Sync_Gateway_RestAPIList)
        SGStats_CumulativeJsonout=Merge_JsonDicts(SGStats_List_Dicts)
        GetSyncGatewayParam_Dict(SGStats_CumulativeJsonout,Microsvcs_Params,SyncGateway_restout_Status)

def GetCumulativeSyncGatewayJson_Output(Sync_Gateway_Rest_Apis):
    global SGStats_List_Dicts
    SGStats_List_Dicts = []
    session_obj = requests.Session()
    Sync_Gateway_Rest_Apis_List = Sync_Gateway_Rest_Apis.split(',')
    for Sync_Gateway_api in Sync_Gateway_Rest_Apis_List:
        Get_SyncGW_rest_api_data(Sync_Gateway_api,session_obj,timeout_val) 
        if SyncGateway_restout_Status == 200: SGStats_List_Dicts.append(dict(SyncGateway_Json_out))

def GetCumulativeSyncGatewayRepJson_Output(Sync_Gateway_Rep_Rest_Apis):
    global SGRepStats_List_Dicts
    SGRepStats_List_Dicts = []
    session_obj = requests.Session()
    Sync_Gateway_Rep_Rest_Apis = Sync_Gateway_Rep_Rest_Apis.split(',')
    for Sync_Gateway_api in Sync_Gateway_Rep_Rest_Apis:
        Get_SyncGWRep_rest_api_data(Sync_Gateway_api,session_obj,timeout_val)
        if SyncGatewayRep_restout_Status == 200: SGRepStats_List_Dicts.append(dict(SyncGatewayRep_Json_out))

def GetSGJson_Handles(Microsvcs_Param):
    if re.search(Microsvcs_Param,syncGateway_changeCache):
            return('syncGateway_changeCache',)
    elif re.search(Microsvcs_Param,syncGateway_db):
            return('syncGateway_db',)
    elif re.search(Microsvcs_Param,syncGateway_rest):
            return ('syncGateway_rest',)
    elif re.search(Microsvcs_Param,syncGateway_stats):
            return('syncGateway_stats',)

def GetSyncGatewayParam_Dict(SG_json_out,Microsvcs_Params,Status):
   global Data_Dict_Merge
   global json_out
   SG_Data_Dict_Merge={}
   SG_Data_Dict_Merge = GetDefault_SG_Data_Dict_Merge(SG_Data_Dict_Merge,Microsvcs_Params)
   if Status == 200:
        for Microsvcs_Param in Microsvcs_Params:
            if Microsvcs_Param not in SyncGWREP_PegParams:
                Json_handles_Microsvcs_Param = GetSGJson_Handles(Microsvcs_Param)
                GetSyncGateway_OneLevel_Dict = SG_json_out[Json_handles_Microsvcs_Param[0]]
                if len(Json_handles_Microsvcs_Param) == 1 and any(Microsvcs_Param in s for s in GetSyncGateway_OneLevel_Dict.keys()):
                    if Microsvcs_Param in ['lag-queue-','lag-tap-','lag-total-','requests_']:
                        (MultiplyAccumulateProduct,Divisor) = MultiplyAccumulateAvgPegVals(GetSyncGateway_OneLevel_Dict,Microsvcs_Param)
                        MultiplyAccumulateAvg=0
                        if MultiplyAccumulateProduct != 0 and Divisor != 0: MultiplyAccumulateAvg = MultiplyAccumulateProduct/Divisor
                        SG_Data_Dict_Merge.update({Microsvcs_Param:MultiplyAccumulateAvg})
                    else:
                        SG_Data_Dict_Merge.update({Microsvcs_Param:GetSyncGateway_OneLevel_Dict[Microsvcs_Param]})
            elif Microsvcs_Param in SyncGWREP_PegParams and Service_Type == 'SYNCGWREP':
                SG_Data_Dict_Merge.update({Microsvcs_Param:SG_json_out[Microsvcs_Param]})
        Data_Dict_Merge=SG_Data_Dict_Merge
        json_out=SG_json_out

def MultiplyAccumulateAvgPegVals(SG_Dict,search_key_in_dict):
    search_key_0000ms=0
    Product = 0
    MultiplyAccumulateProduct=0
    Divisor=0
    MultiplyAccumulateAvg=0
    for search_key in SG_Dict.keys():
        if any(SG_Dict) == True and any(search_key_in_dict in s for s in SG_Dict.keys()) and search_key_in_dict in search_key:
            search_key_multiplier = search_key.split(search_key_in_dict)[1]
            search_key_multiplier = int(search_key_multiplier.split('ms')[0])
            if search_key_multiplier == 0000:
                search_key_0000ms = SG_Dict[search_key]
            else:
                Divisor = Divisor + SG_Dict[search_key]
                Product = Product + search_key_multiplier*SG_Dict[search_key]
    Divisor = Divisor + search_key_0000ms
    MultiplyAccumulateProduct = Product + search_key_0000ms
    return (MultiplyAccumulateProduct,Divisor)

def Get_SyncGW_rest_api_data(url,session_obj,timeout_val):
    global SyncGatewayRep_Json_out
    global SyncGateway_Json_out
    global SyncGateway_restout_Status
    global MicrosvcsPegDataUpdateFlag
    try:
        r = session_obj.get(url, timeout=timeout_val)
        SyncGateway_Json_out = json.loads(r.text)
        if Service_Type == 'SYNCGWREP' and re.search("active_tasks" , url):
            SyncGateway_Json_out = SyncGateway_Json_out[0]
            SyncGatewayRep_Json_out=SyncGateway_Json_out
        SyncGateway_restout_Status = r.status_code
        if SyncGateway_restout_Status == 200:
            MicrosvcsPegDataUpdateFlag=1
    except requests.exceptions.HTTPError:
        printlog('errors',"Error: HTTP Error occured when connecting to %s !!"  %(url))
    except requests.exceptions.InvalidURL:
        printlog('errors',"Error: Valid URL is required when connecting to %s !!"  %(url))
    except requests.exceptions.ConnectionError:
        printlog('errors',"Error: Unable to connect to %s !!"  % (url))
    except requests.exceptions.Timeout:
        printlog('errors',"Error: Timeout occurred to connect to %s !!"  % (url))

def Get_SyncGWRep_rest_api_data(url,session_obj,timeout_val):
    global SyncGatewayRep_Json_out
    global SyncGatewayRep_restout_Status
    global MicrosvcsPegDataUpdateFlag
    try:
        r = session_obj.get(url, timeout=timeout_val)
        SyncGatewayRep_Json_out = json.loads(r.text)
        SyncGatewayRep_Json_out = SyncGatewayRep_Json_out[0]
        SyncGatewayRep_restout_Status = r.status_code
        if SyncGatewayRep_restout_Status == 200:
            MicrosvcsPegDataUpdateFlag=1
    except requests.exceptions.HTTPError:
        printlog('errors',"Error: HTTP Error occured when connecting to %s !!"  %(url))
    except requests.exceptions.InvalidURL:
        printlog('errors',"Error: Valid URL is required when connecting to %s !!"  %(url))
    except requests.exceptions.ConnectionError:
        printlog('errors',"Error: Unable to connect to %s !!"  % (url))
    except requests.exceptions.Timeout:
        printlog('errors',"Error: Timeout occurred to connect to %s !!"  % (url))

def Peginterval_CompleteSnapshot(json_out):
    CurrentDate = commands.getoutput("date +'%Y/%m/%d %H:%M:%S'")
    LogVal_Jsonout = 'Date: ' + str(CurrentDate) + ',' + str(json_out)
    RepFailure_LogVal_Jsonout = 'Date: ' + str(CurrentDate) + ',' + str(SyncGatewayRep_Json_out)
    if Service_Type == 'CBS': 
        printlog('CBSSnapshotinfo',LogVal_Jsonout)
    elif Service_Type == 'SYNCGW':
        printlog('SYNCGWSnapshotinfo',LogVal_Jsonout)
    elif Service_Type == 'SYNCGWREP':
        printlog('SYNCGWREPSnapshotinfo',LogVal_Jsonout)
        printlog('SYNCGWREPReplicationFailureSnapshotinfo',RepFailure_LogVal_Jsonout)
    elif Service_Type == 'RMQ':
        printlog('RMQSnapshotinfo',LogVal_Jsonout)
    elif Service_Type == 'GRIDGAIN':
        printlog('GRIDGAINSnapshotinfo',LogVal_Jsonout)

def GetThresholdValuesPropFile(MicrosvcsPegPropertyFile):
        global MicrosvcsPegPropertyFileFlag
        Threshold_Prop_Dict = {}
        Threshold_Prop_List_Dicts = []
        try:
            with open(MicrosvcsPegPropertyFile) as f:
                for line in f.read().splitlines():
                    Threshold_Dict_Str = line.rstrip().split('=')[1]
                    if Threshold_Dict_Str == '':
                        MicrosvcsPegPropertyFileFlag=0  
                    Threshold_Dict = json.loads(Threshold_Dict_Str)
                    Threshold_Prop_List_Dicts.append(dict(Threshold_Dict))
                    MicrosvcsPegPropertyFileFlag=1
        except:
            printlog('errors',"Peg property File %s has incorrect Format/Consul has not synched"%(MicrosvcsPegPropertyFile))
        return Threshold_Prop_List_Dicts

def GetThresholdPropDictPegID(Threshold_Prop_List_Dicts,PegID):
    for Threshold_Prop_Dict in Threshold_Prop_List_Dicts:
        if PegID in Threshold_Prop_Dict.values():
            return Threshold_Prop_Dict

def KPIPegging_Microsvcs(Threshold_Prop_Dict,MvcsPegObj,UTC_Start_Time,UTC_End_time,Knpegformatter):
    KPIMO_instance = Threshold_Prop_Dict['managementobjectinstance']
    OM_Name = Threshold_Prop_Dict['omname']
    OM_Type = int(Threshold_Prop_Dict['omtype'])
    KPIMO_instance = re.sub('["]', '', KPIMO_instance)
    OM_Name = re.sub('["]', '', OM_Name)
    DG_KPILog_Strng = Get_DGKPI_LogStrng(KPIMO_instance,OM_Name,Knpegformatter)
    Sysloglocaltimestamp = time.strftime("%b %d %H:%M:00") 
    if OM_Type == 1:
        PegValue = float(MvcsPegObj.data)
    elif OM_Type == 4:
        MvcsPegObj.UpdateAvgOfMicrosvcsPeg()
        PegValue = MvcsPegObj.Average
    elif OM_Type == 5:
        PegValue = float(MvcsPegObj.current)
    PegValue = str(abs(PegValue))
    Syslog_KPI_Tag=Knpegformatter.SYSLOG_KPI_TAG
    KPILogmessage = Syslog_KPI_Tag+DG_KPILog_Strng + ',' + PegValue + ',' + UTC_Start_Time + ',' + UTC_End_time
    printlog('RLSSnapshot',"%s"  % (KPILogmessage))
    Knpegformatter.send_syslog(KPILogmessage)

    CurrentDate = commands.getoutput("date +'%Y/%m/%d %H:%M:%S'")
    MvcsPegObj.data=0
    MvcsPegObj.Average=0
    MvcsPegObj.Count = 0
    MvcsPegObj.ThresholdCount = 0

def Get_DGKPI_LogStrng(KPIMO_instance,OM_Name,Knpegformatter):
    DG_KPILog_Strng = Knpegformatter.KPI_PREFIX + Knpegformatter.SIGNALINGCARDNAME + ',' + Knpegformatter.PTTSERVERID + ',' +Knpegformatter.SIGNALINGCARDID + ',' + KPIMO_instance + ',' + 'A' + ','+ OM_Name
    return DG_KPILog_Strng

def PollPegPropertiesFile():
    path_to_watch = '/DG/activeRelease/dat/'
    before = dict ([(f, None) for f in os.listdir (path_to_watch)])
    PegPropertyFileName = path_to_watch+Service_Type+'Pegs'+'.'+'properties'
    after = dict ([(f, None) for f in os.listdir (path_to_watch)])
    added = [f for f in after if not f in before]
    if not os.path.isfile(PegPropertyFileName):
        printlog('errors',"ServiceType: %s Peg Property File is not present in :%s"  % (Service_Type,path_to_watch))

def Resolve_WebAlarmURLPropFile(PropertyFilePath,WebAlarm_Fqdn,WebAlarm_generate_url):
    global WebAlarm_Url
    global WebAlarmUrlResolveFlag
    AlarmSvc_Strg = 'AlarmService'
    try:
       with open(PropertyFilePath) as f:
            for line in f.read().splitlines():
                line=[x.strip(' ') for x in line.rstrip().split('=')]
                if line[0] == WebAlarm_Fqdn and AlarmSvc_Strg in line[1]:
                    WebAlarm_Url = WebAlarm_generate_url.replace('IP_address', line[1])
       WebAlarmUrlResolveFlag=1 
    except:
      printlog('errors',"Failure: Web Alarm URL Resolution/Web Card may not be present in set up/ALARMSERVICE service may not running in Web Card")

def GetWebAlarmJsonPayloadPegID(Alarm_Code,Alarm_Severity):
    headers = {'content-type': 'application/json'}
    json_payload = {}
    json_out_Alarm = {}
    MOInfo = Service_Version+':'+Service_Type+':'+Local_NodeIP_address+':'+Local_NodeIP_address 
    json_payload['alarmCode'] = Alarm_Code
    json_payload['alarmSeverity'] = Alarm_Severity
    json_payload['serviceName'] = Service_Type
    json_payload['timestamp'] = Get_UTC_epoch()*1000
    json_payload['moClasstype'] = 5
    json_payload['pptserverId'] = Ptt_Server_ID
    json_payload['moInfo'] = ':IP:'+Local_NodeIP_address+':'+MOInfo
    json_payload['moInsatance'] = Signalling_card_ID
    json_payload['message'] = ''
    json_out_Alarm['alarmList'] = [json_payload]
    json_out_Alarm['pttServerId'] = Ptt_Server_ID
    json_payload = {}

    return (json_out_Alarm,headers)

def Get_UTC_epoch():
    d = datetime.utcnow()
    utc_epoch = calendar.timegm(d.utctimetuple())
    return utc_epoch

def GetDefault_SG_Data_Dict_Merge(SG_Data_Dict_Merge,Microsvcs_Params):
    for Microsvcs_Param in Microsvcs_Params:
        SG_Data_Dict_Merge[Microsvcs_Param] = 0
    return SG_Data_Dict_Merge

def GetGGainRestAPIUri(DatFilePath):
    global GridGain_Url
    with open(DatFilePath) as f:
        string=f.read()
        GGUri=re.search(r"http.*ServicePlaneIPAddressOfNode",string)
        GridGain_Url=GGUri.group()

def Resolve_GGain_SvcPlaneIP(CointaineriniFile):
    global GridGain_Url
    global Grid_SvcPlaneIP_ResolveFlag
    SvcPlaneIPStrg='SERVICEPLANE_IP_ADDRESSES'
    try:
        with open(CointaineriniFile) as f:
            for line in f.read().splitlines():
                line = line.rstrip().split('=')
                if line[0] == SvcPlaneIPStrg:
                    GridGain_Url = GridGain_Url.replace('ServicePlaneIPAddressOfNode', line[1])
                    Grid_SvcPlaneIP_ResolveFlag=1
    except:
        printlog('errors',"Failure: Grid Gain SERVICEPLANE_IP_ADDRESSES is not present in cointainer ini File")

def PostConsulKV(KVFlag):
    global ConsulKV

    ConsulKVReq = "http://127.0.0.1:8500/v1/agent/check/fail/CONTAINER_PLATFORM_HEALTH"

    if KVFlag == 0:
	ConsulKVReq = "http://127.0.0.1:8500/v1/agent/check/pass/CONTAINER_PLATFORM_HEALTH"

    try:
        r = requests.put(ConsulKVReq)
        printlog('monitor_log',"Consul KV Request success for: %s"  %(ConsulKVReq))
    except requests.exceptions.HTTPError:
        printlog('errors',"Error: HTTP Error occured when connecting to %s !!"  %(ConsulKVReq))
    except requests.exceptions.InvalidURL:
        printlog('errors',"Error: Valid URL is required when connecting to %s  !!"  %(ConsulKVReq))
    except requests.exceptions.ConnectionError:
        printlog('errors',"Error: Unable to connect to %s !!"  % (ConsulKVReq))
    except requests.exceptions.Timeout:
        printlog('errors',"Error: Timeout occurred to connect to %s !!"  % (ConsulKVReq))

    ConsulKV = KVFlag 

def GetModifiedPegValue(Microsvcs_PegID,PegValue,json_out):
    if Microsvcs_PegID == 36327: PegValue=(float(PegValue)/float(json_out['response']['metrics']['heapMemoryCommitted']))*100
    return PegValue

if __name__ == "__main__":
    # Procedure to run as a daemon process.
    # Change to our working directory first.
    # Fork now.
    if len(sys.argv) > 1:
        monitor_log_directory = sys.argv[1]
    print "Reports will be logged to:", monitor_log_directory
    
    countsys = 0
    if os.fork(): 
        # Parent process exits here.
        os._exit(0)
    # Child process - make session leader. 
    os.setsid()
    # Detach from the console by closing stdin,
    # stdout and stderr.

    for fd1 in range(3):
        os.close(fd1)
    # Set std input/output/error to /dev/null.
    os.open('/dev/null', os.O_RDONLY)
    os.open('/dev/null', os.O_WRONLY)
    os.open('/dev/null', os.O_WRONLY)

    # Done. Fork again. 
    if os.fork():
        # Parent exits here.
        os._exit(0)
    # From here on, the child process is detached
    # from the console.
    
    os.system('mkdir -p %s' % monitor_log_directory)
    # Change our working directory. All relative paths will now
    # be relative to this directory.
    os.chdir(monitor_log_directory)
    # Create a logmanager instance 
    DiskPartitionDet = commands.getoutput("/bin/df -Ph | grep -v 'Filesystem' | grep -v 'PostgresData' | awk -F' ' '{print $6}' 2>>/dev/null").split("\n")

    log_manager = LogManager()
    DockerPegCPU = PegData(12503)
    DockerPegIdle = PegData('DockerSysIdle')
    DockerPegContainerCache = PegData('DockerSysCache')
    DockerPegContainerTotalMem = PegData('DockerSysTotalMem')
    DockerPegContainerTotalMemUsed = PegData(12502)
    DockerPegContainerTotalMemFree = PegData('DockerSysTotalFreeMem')
    DockerPegContainerMemCache = PegData('DockerSysMemCache')
    DockerPegContainerMemoryRSSUsage = PegData(12515)
    
    DGPartitionUsed = PegData(152)
    DGlogsPartitionUsed = PegData(153)
    VarPartitionUsed = PegData(154)
    DGdataPartitionUsed = PegData(165)
    DatabasePartitionUsed = PegData(166)
    SwapMemUsed = PegData(171)
    CouchDataPartitionUsed = PegData(35077)
    CouchIndexPartitionUsed = PegData(35078)
    PostGresDataPartitionUsed = PegData(38001)
    PostGresDataBackupPartitionUsed = PegData(38002)
    RTXMemoryUsage = PegData(150)
    RTXMemoryUsageWithoutSwap = PegData(155)

    PartitionHash = {}
    for Partition in DiskPartitionDet:
       ParitionFlag = 0
       for PegID in PegIDMap.keys():
           if PegIDMap[PegID]['Name'] == Partition:
              ParitionFlag = 1
              break
       if ParitionFlag == 0:
           PartitionHash[Partition] = PegData(Partition)

    if Service_Type == 'SYNCGWREP':
       ReplicationLagPeg = PegData(33232)
       DockerPegObjsHash[33232] = ReplicationLagPeg
    ######################### Create Docker/Platform PegObj hash ############################################################
    DockerPegObjsHash[12503] = DockerPegCPU
    DockerPegObjsHash[12502] = DockerPegContainerTotalMemUsed
    DockerPegObjsHash[12515] = DockerPegContainerMemoryRSSUsage
    DockerPegObjsHash[152] = DGPartitionUsed
    DockerPegObjsHash[153] = DGlogsPartitionUsed
    DockerPegObjsHash[154] = VarPartitionUsed
    DockerPegObjsHash[165] = DGdataPartitionUsed
    DockerPegObjsHash[166] = DatabasePartitionUsed
    DockerPegObjsHash[171] = SwapMemUsed
    DockerPegObjsHash[35077] = CouchDataPartitionUsed
    DockerPegObjsHash[35078] = CouchIndexPartitionUsed
    DockerPegObjsHash[38001] = PostGresDataPartitionUsed
    DockerPegObjsHash[38002] = PostGresDataBackupPartitionUsed
    DockerPegObjsHash[150] = RTXMemoryUsage
    DockerPegObjsHash[155] = RTXMemoryUsageWithoutSwap

    if Service_Type == 'PostgreSQL':
        PostGresDBArr = ('postgres','art','hive','grafana','keycloak','rundeck','idap_prod')

        for DBName in PostGresDBArr:
            ConnectionHash = {'dbname':DBName,'username':'postgres','password':'postgres','hostname':'127.0.0.1','port':5432,'logenable':0}
            PostGresConnHash[DBName] = PGDBMgr.PGDBMgr(ConnectionHash)

    
    ServiceType=Service_Type
    MicrosvcsPropertyFile = PropertyFilePath+'CommonConfig'+'.properties'
    
    #--------------------------- Read CBS Property File for Admin UID/PW INT-27854 ------------------------------------------#
    if Service_Type == 'CBS':
        (CBSUserID,CBSPassword)=GetDatafromPropertyFile('/DG/activeRelease/dat/couchbase/default.properties')
    ##########################################################################################################################
    if Service_Type == 'CBS' or Service_Type == 'SYNCGW' or Service_Type == 'SYNCGWREP' or Service_Type == 'RMQ' or Service_Type == 'GRIDGAIN':
       ##### Validating presence of the following Files #######################################################################
       ####### SERVICETYPE.properties File in /DG/activeRelease/dat/ ##########################################################
       ####### SERVICETYPEPegs.properties File in /DG/activeRelease/dat/ ######################################################
       ####### MicrosvcsDatFile File in /DG/activeRelease/dat/ ################################################################
       ########################################################################################################################
       ####################### Poll for PegProperty File  ####################################################################
       if Service_Type == 'SYNCGWREP':
            ServiceType='SYNCGW'
       PollPegPropertiesFile()
       MicrosvcsPegPropertyFile=PropertyFilePath+ServiceType+'Pegs'+'.properties'
       MicrosvcsCointaineriniFile=PropertyFilePath+'containerinit.ini'
       MicrosvcsdatFile = '/DG/activeRelease/Tools/Fieldutils/'+'MicrosvcsDatFile'
       while 1:
            if not os.path.isfile(MicrosvcsPegPropertyFile) or not os.path.isfile(MicrosvcsdatFile):         
                printlog('errors',"%s or %s is not present"  % (MicrosvcsPegPropertyFile,MicrosvcsdatFile))
                time.sleep(5)
            else:
                break
            ################ Gets a complete list of Threshold value dicts for each PegID from SERVICETYPEPegdata.properties #######
       Threshold_Prop_List_Dicts=GetThresholdValuesPropFile(MicrosvcsPegPropertyFile)
       ##### Creating Microsvcs Peg data objects Dict. from MicrosvcsDatFile  #################################################
       if MicrosvcsPegPropertyFileFlag == 1:
            MicrosvcsPegObjsHash={}
            MicroservDatParams=SG_PegIDS_Params
            if Service_Type == 'CBS':
                MicroservDatParams=CBS_PegIDS_Params
            elif Service_Type == 'SYNCGWREP':
                MicroservDatParams=SGREP_PegIDS_Params
            elif Service_Type == 'RMQ':
                MicroservDatParams=RMQ_PegIDS_Params
            elif Service_Type == 'GRIDGAIN':    
                GetGGainRestAPIUri(MicrosvcsdatFile)
                Resolve_GGain_SvcPlaneIP(MicrosvcsCointaineriniFile)
                MicroservDatParams=GridGain_PegIDS_Params
       ################## MicrosvcsDatFile dat File ##########################################################################
       ################# Create a mapping b/w PegName and PegID ##############################################################
            Microsvcs_PegIDS_ParamDict=GetMicrosvcs_PegIDParamsOrderedDict(MicroservDatParams)
            for Pegname,Pegid in Microsvcs_PegIDS_ParamDict.items():
                Pegid = int(Pegid)
                MicrosvcsPegObjsHash[Pegid] = PegData(Pegid)
    #########################################################################################################################

    if not os.path.isfile(MicrosvcsPropertyFile):
       printlog('errors',"%s is not present"  % MicrosvcsPropertyFile)
       
    Resolve_WebAlarmURLPropFile(MicrosvcsPropertyFile,WebAlarm_Fqdn,WebAlarm_generate_url)
    Alarm_obj = Alarms()
    Knpegformatter = KnCollectdStatsDPegFormatter(Syslog_Kpi_Tag,Kpi_prefix, Signalling_card_name, Ptt_Server_ID, Signalling_card_ID, Rsyslog_host, Rsyslog_port, Syslog_src_port, Kpi_log_path)
    Knpegformatter.syslogIns = Syslog(Knpegformatter.RSYSLOGHOST, Knpegformatter.RSYSLOGPORT,  Knpegformatter.SYSLOG_PROXY_SRCPORT) 	
    crython.tab.start()

    flag = 0

    PROCESSORS = commands.getoutput("cat /proc/cpuinfo 2>>/dev/null | grep processor | wc -l").strip()
    LOGSVNAME = os.environ.get("SERVICETYPE")
    if RTXType == 4:
        LOGSVNAME = os.environ.get("SERVERTYPE")
    hostname  = commands.getoutput("hostname 2>>/dev/null").strip()
    LOCAL_IP_ADDRESS = os.environ.get("LOCAL_IP_ADDRESS")

    temp = commands.getoutput("/usr/local/bin/reg_read 2>>/dev/null")
    temp = temp.split('\n') 
    arr=[]
    for line in temp:
        arr.append(line)
    for val in arr:
        matchObj = re.match( r'Blade ID is\s*(.*)', val, re.M)
        if matchObj:
           if matchObj.group(1) != '':
              hardwaretype = matchObj.group(1)
              if hardwaretype == 'cp6010':
                 hardwaretype = 'Proc200'
              elif hardwaretype == 'cp6014':
                 hardwaretype = 'Proc300'
              else:
                 hardwaretype = 'UNKNOWN' 
              flag = 1
              break

    if flag == 0 or ReleaseVal == 7:
       hardwaretype = 'VIRTUAL'

    pttid = None
    try:
        # Try to infer the system type.
        sys_type = get_system_type()
        sys_types = sys_type.split('-')

        if len(sys_types) == 1:
            process_set = process_sets[sys_type]
        else:
            process_set = []
            for sys_type in sys_types:
                for process in process_sets[sys_type]:
                    if process_set.count(process) == 0:
                        process_set.append(process) 

        # Get information on the hardware configuration.
        # Can be useful when interpreting the results.
        procps_patched, processors = check_system_configuration()
        reader = ProcReader(processors,process_set,procps_patched)

        #######################################################
        # Customize the following map if you want to monitor
        # any new system parameter. The format is:
        # 'logfilename':'shell command'
        # This list is for commands that are to be run once
        # per sampling interval. Customize the next map for
        # parameters that need continuous monitoring.
        ########################################################
       
        if int(RTXType) == 4:
           netstatcmd = 'netstat -anpt'
        else:
           netstatcmd = 'netstat -anp'
 
        monitored_data = {
            'disk_usage':'echo Date:;date;df -Pk',
            'Memory_usage':'echo Date:;date;cat /proc/meminfo',
            'wchan':'ps -emo pid,ppid,cmd,wchan ',
            'netstat':'echo Date:;date;%s' %(netstatcmd)
        }

        #######################################################
        # Customize the following map if you want to monitor
        # any new system parameter continously. For example
        # running sar or iostat for a single sample does not
        # give meaningful data. These commands should run over
        # multiple sampling intervals.
        # The format is:
        # 'logfilename':'shell command'
        ########################################################
        monitored_data_continuous = {
            'iostat':'iostat -x -t -c -d %d' % System_poll_interval,
            'topoutput':'top -b -d %d' % System_poll_interval,
            'sar':'sar -u -r -S -W -B -n DEV %d' % System_poll_interval,
            'iotopoutput':'iotop -b -d %d' % System_poll_interval
        }
        
        if Service_Type == 'PostgreSQL':
            PostGresDBSnapshot = {
                    'PostGres_ConnectionDet' : 'count|datname|pid|client_addr;Select count(*),datname,pid,client_addr from pg_stat_activity group by datname,pid,client_addr order by count desc',
                    'PostGresRepLag':'lag_bytes|pid|application_name;SELECT pg_xlog_location_diff(pg_current_xlog_insert_location(), flush_location) AS lag_bytes,pid, application_name FROM pg_stat_replication',
                    'PostGresRepLag_RetBytes':"slot_name|database|active|retained_bytes;SELECT slot_name, database, active,pg_xlog_location_diff(pg_current_xlog_insert_location(), restart_lsn) AS retained_bytes FROM pg_replication_slots WHERE plugin = 'bdr'",
                    'PostGres_SharedBufHits':"relname|heap_blks_read|heap_blks_hit|idx_blks_read|idx_blks_hit;select relname,heap_blks_read,heap_blks_hit,idx_blks_read,idx_blks_hit from pg_statio_user_tables",
                    'PostGres_WaitSess':"count|pid|client_addr|datname;select count(*),pid,client_addr,datname from pg_stat_activity where waiting is true group by pid ,client_addr,datname",
                    'PostGres_BGWriter_CheckPoint_Monitor':"checkpoints_timed|checkpoints_req|checkpoint_write_time|checkpoint_sync_time|stats_reset;Select checkpoints_timed,checkpoints_req,checkpoint_write_time,checkpoint_sync_time,stats_reset from pg_stat_bgwriter"
                    }
            
            PostGresDBSnapshotView = {
                    'PostGres_LRT': "session_start_time|current_query_run_time|duration_in_current_state|query_state|pid|datname|query|client_hostname|client_addr|application_name;select (now() - backend_start),(now() - xact_start),(now()- state_change),state,pid,datname,query,client_hostname,client_addr,application_name,from pg_stat_activity,where state in ('active','idle') and ((now() - pg_stat_activity.state_change)) > '1 minutes' and query not like 'bdr_apply%' and application_name not like 'bdr%' order by duration_in_current_state desc"
                    }

            PostGresDSNSnapshot = {
                    'PostGres_BDR': "rilocalid|riremoteid|nr_commit|nr_rollback|nr_insert|nr_insert_conflict|nr_update|nr_update_conflict|nr_delete|nr_delete_conflict|nr_disconnect;select rilocalid,riremoteid,nr_commit,nr_rollback,nr_insert,nr_insert_conflict,nr_update,nr_update_conflict,nr_delete,nr_delete_conflict,nr_disconnect from bdr.pg_stat_bdr",
                    'PostGres_BlockHitRead_Table_Monitoring':"heap_read|heap_hit|ratio;SELECT sum(heap_blks_read),sum(heap_blks_hit),sum(heap_blks_hit) / (sum(heap_blks_hit) + sum(heap_blks_read)) from pg_statio_all_tables where schemaname not in('bdr','pg_toast','pg_catalog','information_schema')",
                    'PostGres_BlockHitRead_Index_Monitoring':"idx_read|idx_hit|ratio;SELECT sum(idx_blks_read),sum(idx_blks_hit),(sum(idx_blks_hit) - sum(idx_blks_read)) / sum(idx_blks_hit) from pg_statio_all_indexes where schemaname not in('bdr','pg_toast','pg_catalog','information_schema')"
                    }

        matchObj = re.match( r'.*(EGLS|SYNCGW|PTMSG).*', str(LOGSVNAME), re.M)
        if matchObj: 
            MaxSubs = commands.getoutput("grep MAX_SUBSCRIBERS /DG/activeRelease/dat/CommonConfig.properties |  awk -F'=' '{print $2}' | sed -e 's/ *//'")
            if MaxSubs == '':
               MaxSubs = 100000

            if int(MaxSubs) > 10000:
               monitored_data_continuous['heapinfo'] = '/DG/activeRelease/Tools/Fieldutils/heaprun.sh start'

        continuous_data_files = start_continuous_data_monitoring\
            (monitored_data_continuous,1)
        secs_from_prev_rotate = 0
        Systemtime = time.time()
        Pegtime = Systemtime
        ViewQryTime = Systemtime
        Processtime = Systemtime
        PostGresDSNtime = Systemtime
        PostConsulKV(0)
        GetActiveEMSConn()

        if Service_Type == 'PostgreSQL':
           for DBName in PostGresConnHash.keys():
               GetPostGresConnection(PostGresConnHash[DBName])

        while 1:
            # Record beginning of sampling interval
            t1 = time.time()

            if t1 - PostGresDSNtime >= Postgres_poll_interval or countsys == 0 or t1 - PostGresDSNtime < 0:
	            if Service_Type == 'PostgreSQL':
		           for DBName in PostGresConnHash.keys():
		                for logfile in PostGresDSNSnapshot.keys():
		                   if logfile == 'PostGres_BDR' and DBName != 'keycloak':
		                      continue
		                   QryDetArr = PostGresDSNSnapshot[logfile].split(';')
		                   Status,Output = PostGresDBExecute(QryDetArr[1],PostGresConnHash[DBName])
		                   if Status != -1:
		                      Date = commands.getoutput('date')
		                      printlog(logfile,"DSN:"+DBName+","+Date+"")
		                      printlog(logfile,QryDetArr[0])
		                      for QryOut in Output:
		                          OutStr = '|'.join([str(x) for x in QryOut])
		                          printlog(logfile,OutStr)
	            PostGresDSNtime = t1

            if t1 - Systemtime >= System_poll_interval or countsys == 0 or t1 - Systemtime < 0:
	            for log_file in monitored_data.keys():
		           printlog(log_file,commands.getoutput(monitored_data[log_file]))
                
	            if Service_Type == 'PostgreSQL':
		           for logfile in PostGresDBSnapshot.keys():
		                QryDetArr = PostGresDBSnapshot[logfile].split(';')
		                Status,Output = PostGresDBExecute(QryDetArr[1],PostGresConnHash['postgres'])
		                if Status != -1:
		                   Date = commands.getoutput('date')
		                   printlog(logfile,"DSN:postgres,"+Date+"")
		                   printlog(logfile,QryDetArr[0])
		                   for QryOut in Output:
		                       OutStr = '|'.join([str(x) for x in QryOut])
		                       printlog(logfile,OutStr)
	            Systemtime = t1

            if t1 - ViewQryTime >= ViewQry_poll_interval or countsys == 0 or t1 - ViewQryTime < 0:
                if Service_Type == 'SYNCGWREP':
                   ReplicationLagPeg.GetValueOfPeg()
                
                if Service_Type == 'PostgreSQL':
                   for logfile in PostGresDBSnapshotView.keys():
                        QryDetArr = PostGresDBSnapshotView[logfile].split(';')
                        Status,Output = PostGresDBExecute(QryDetArr[1],PostGresConnHash['postgres'])
                        if Output != -1:
                           Date = commands.getoutput('date')
                           printlog(logfile,"DSN:postgres,"+Date+"")
                           printlog(logfile,QryDetArr[0])
                           for QryOut in Output:
                               OutStr = '|'.join([str(x) for x in QryOut])
                               printlog(logfile,OutStr) 
                ViewQryTime = t1
                
            if t1 - Pegtime >= Peg_poll_interval or countsys == 0 or t1 - Pegtime < 0:
                DockerPegCPU.GetValueOfPeg()
                DockerPegIdle.GetValueOfPeg()
                DockerPegContainerCache.GetValueOfPeg()
                DockerPegContainerTotalMem.GetValueOfPeg()
                DockerPegContainerTotalMemUsed.GetValueOfPeg()
                DockerPegContainerTotalMemFree.GetValueOfPeg()
                DockerPegContainerMemCache.GetValueOfPeg()
                DockerPegContainerMemoryRSSUsage.GetValueOfPeg()

                DGPartitionUsed.GetPartitionUsedVal()
                DGlogsPartitionUsed.GetPartitionUsedVal()
                VarPartitionUsed.GetPartitionUsedVal()
                DGdataPartitionUsed.GetPartitionUsedVal()
                DatabasePartitionUsed.GetPartitionUsedVal()
                SwapMemUsed.GetPlatformMemVal()
                RTXMemoryUsage.GetPlatformMemVal()
                RTXMemoryUsageWithoutSwap.GetPlatformMemVal()

                if Service_Type == 'CBS':
                   CouchDataPartitionUsed.GetPartitionUsedVal()
                   CouchIndexPartitionUsed.GetPartitionUsedVal()
                
                if Service_Type == 'PostgreSQL':
                   PostGresDataPartitionUsed.GetPartitionUsedVal()
                   PostGresDataBackupPartitionUsed.GetPartitionUsedVal()
                
                for Partition in PartitionHash.keys():
                   PartitionHash[Partition].GetPartitionUsedVal()

                ClearCheckFlag = 0
                for pegid in PegIDMap:
                   if 'ConsulKVPost' in PegIDMap[pegid]:
                       if PegIDMap[pegid]['ConsulKVPost'] == 1:
                          if ConsulKV == 0:
                             PostConsulKV(1)
                             break
                          ClearCheckFlag = 1
                
                if ClearCheckFlag == 0 and ConsulKV == 1:
                   PostConsulKV(0)

                ############### CBS_Testing #############################################################################################
                if (Service_Type == 'CBS' or Service_Type == 'SYNCGW' or Service_Type == 'SYNCGWREP' or Service_Type == 'RMQ' or Service_Type == 'GRIDGAIN') and (MicrosvcsPegPropertyFileFlag == 1):
                     if Service_Type == 'CBS':
                        GetValueof_CBS_Peg()
                     elif Service_Type == 'SYNCGW' or Service_Type == 'SYNCGWREP':
                        GetValueof_SG_Peg()
                     elif Service_Type == 'RMQ':
                        GetValueof_RMQ_Peg()
                     elif Service_Type == 'GRIDGAIN':
                        GetValueof_GRIDGAIN_Peg()
                     if MicrosvcsPegDataUpdateFlag == 1:
                        Peginterval_CompleteSnapshot(json_out)  
                        for Microsvcs_Param in Microsvcs_PegIDS_ParamDict.keys():
                            Microsvcs_PegID = int(Microsvcs_PegIDS_ParamDict[Microsvcs_Param])
                            Threshold_Prop_Dict = GetThresholdPropDictPegID(Threshold_Prop_List_Dicts,Microsvcs_PegID)
			    #### INT-34005 #############################################################################	
			    PegValue=Data_Dict_Merge[Microsvcs_Param]
                            if Microsvcs_PegID in [36327]:
                                PegValue=GetModifiedPegValue(Microsvcs_PegID,PegValue,json_out)	 	
			    ###########################################################################################	
                            MicrosvcsPegObjsHash[Microsvcs_PegID].UpdateMicrosvcs_PegData(PegValue,Threshold_Prop_Dict)
                        Data_Dict_Merge={}
                        json_out={}
                        CBStats_List_Dicts=[]
                Pegtime = t1

            # Take readings for each process with the stagger delay
            if t1 - Processtime >= Process_poll_interval or countsys == 0 or t1 - Processtime < 0:
            ########################################################################################################################
                if process_monitoring:
                    for i in range(len(process_set)):
                        reader.update_data()
                        time.sleep(stagger_delay)
                Processtime = t1
                ####################################################################################################################
                # Record end of sampling interval.
            t2 = time.time()
            # Sleep for the remaining period of the poll interval
            if countsys == 0:
               printlog('systemstat',"LOGSVNAME "+str(LOGSVNAME)+"")
               printlog('systemstat',"LOCAL_IP_ADDRESS "+LOCAL_IP_ADDRESS+"")
               printlog('systemstat',"HOSTNAME "+hostname+"")
               printlog('systemstat',"HARDWARE_TYPE "+hardwaretype+"")
               printlog('systemstat',"rotate_interval "+str(rotate_interval)+"")
               printlog('systemstat',"Process_poll_interval "+str(Process_poll_interval)+"")
               printlog('systemstat',"System_poll_interval "+str(System_poll_interval)+"")
               printlog('systemstat',"Peg_poll_interval "+str(Peg_poll_interval)+"")
               printlog('systemstat',"ViewQry_poll_interval "+str(ViewQry_poll_interval)+"")
               printlog('systemstat',"Postgres_poll_interval "+str(Postgres_poll_interval)+"")
               printlog('systemstat',"PROCESSORS "+str(PROCESSORS)+"")
               printlog('systemstat',"RELEASEVER "+str(ReleaseVal)+"")
               LocalDate = commands.getoutput("date")
               UTCDate = commands.getoutput("date -u")
               printlog('systemstat',"LOCALTIME "+str(LocalDate)+"")
               printlog('systemstat',"UTCTIME "+str(UTCDate)+"")
            
            #################### Changed Process_poll_interval to Peg_poll_interval ######################################   
            countsys = 1 
            if (t2 - t1) < Peg_poll_interval and t2 - t1 > 0:
                time.sleep(Peg_poll_interval - (t2-t1))
            else:
                # If we took longer than the poll interval to
                # collect data, log an error. Can happen when
                # the system is heavily loaded.
                printlog('errors',"Data collection time exceeded poll interval. t2-t1='"+str((t2-t1))+"")
                printlog('errors','This could be due to heavy load on the system.')
            secs_from_prev_rotate += Peg_poll_interval
            if secs_from_prev_rotate >= rotate_interval:
                # Close all open log files.
                secs_from_prev_rotate = 0
                countsys = 0
                closed_continuous_data_files = continuous_data_files[:]
                continuous_data_files = \
                    start_continuous_data_monitoring(monitored_data_continuous,1)
                # This also checks for stale reports to be deleted.

                files_closed = log_manager.rotate()
                # Tar the closed files now.
                archive_list = ''
                for file_name in files_closed:
                    archive_list += file_name + ' '
                archive_list += ' '.join(closed_continuous_data_files) 
                try:
                   os.system(('/bin/nice -n +19 tar -vczf %s.tgz '+archive_list) % \
                       log_manager.get_log_name('reports'))
                except:
                   pass 
                os.system('rm -f '+archive_list)
    except KeyboardInterrupt:
        for process in monitored_data_continuous.keys():
            os.system('pkill -f "%s"' % monitored_data_continuous[process])
            os.system('pkill top')
            os.system('pkill iotop')
            os.system('pkill iostat')
            os.system('pkill sar')
            os.system('pkill sadc')

            matchObj = re.match( r'.*(EGLS|SYNCGW|PTMSG).*', str(LOGSVNAME), re.M)
            if matchObj:
                os.system('sh /DG/activeRelease/Tools/Fieldutils/heaprun.sh stop')

        closed_continuous_data_files = continuous_data_files[:]
        continuous_data_files = \
            start_continuous_data_monitoring(monitored_data_continuous,0)
        # This also checks for stale reports to be deleted.

    	files_closed = log_manager.rotate()
        # Tar the closed files now.
        archive_list = ''
        for file_name in files_closed:
              archive_list += file_name + ' '
        archive_list += ' '.join(closed_continuous_data_files) 
        try:
              os.system(('/bin/nice -n +19 tar -vczf %s.tgz '+archive_list) % \
                   log_manager.get_log_name('reports'))
        except:
              pass 
        os.system('rm -f '+archive_list)
        
    except:
        printlog('errors','Unknown exception. Logging backtrace.')    
        import traceback
        traceback.print_exc(20, printlog('errors',''))

#Modified on 9/21/2018 11:47 PM
