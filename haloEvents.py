#!/usr/bin/python
import sys
import platform
import os
import binascii
import atexit
import codecs
import locale
import threading
import ast
import time
import signal

import cpapi
import cputils

# checks for version 2.6 or 2.7, earlier or later versions may not work
cputils.checkPythonVersion()

import os.path
import json

# Here, we simultaneously check for which OS (all non-Windows OSs are treated equally) we have.
isWindows = True
if (platform.system() != "Windows"):
    isWindows = False
    import cpsyslog
    if sys.stdout.encoding == None:
        # this indicates we're sending to a pipe, and need to force terminal encoding
        sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout)

# Now we check for whether the extra modules needed for syslog functionality are present.
syslogAvailable = True
try:
    if (isWindows):
        import remote_syslog
    else:
        import syslog
except ImportError:
    syslogAvailable = False

redisFailoverAvailable = True
redisAvailable = True
try:
    from redis_failover import RedisFailover
except ImportError:
    redisFailoverAvailable = False
    try:
        import redis
    except ImportError:
        redisAvailable = False

# global vars
shouldExit = False
events_per_page = 100
apiURL = None # if None, use default in cpapi module
apiPort = None # if None, use default in cpapi module
oneEventPerLine = True
lastTimestamp = None
verbose = False
configFilename = "haloEvents.config"
authFilenameDefault = "haloEvents.auth"
authFilenameList = []
timestampPerAccount = {}  # indexed by .auth file prefix, returns ISO-8601 timestamp
# path to the lock file depends on OS
if (platform.system() != "Windows"):
    pidFilename = "/tmp/haloEvents.lock"
else:
    pidFilename = "/haloEvents.lock"
outputFormat = "json-file"
outputDestination = None
metadataDestination = 'file'
useHA = False
syslogOpen = False
syslogInfo = None
outfp = None
fileAppend = True
configDir = None

# config vars for optional redis output
redis_host = None
redis_port = None
redisConnection = None
redisConnected = False
redisDateList = []
redisLockTimeout = 300
redisLockToken = binascii.b2a_hex(os.urandom(15))
redisAccountTimePrefix = "lastTimestamp."
redisUnreadPrefix = "unread."
haConfigFile = "ha.config"

# constants used for CEF output
cefVersion = 0
cefVendor = "CloudPassage"
cefProduct = "CPHalo"
cefProductVersion = "1.0"
cefHaloGrid = "50.57.180.190"
cefHeaderList = ["name", "critical"]
cefFieldMapping = {
    "server_ip_address": "dst",
    "server_hostname": "dhost",
    "message": "msg",
    "created_at": "rt",
    "actor_ip_address": "src",
    "actor_username": "duser",
    "object_name": "fname"
}
# next fields get mapped, in this order, to the first Custom String (cs) fields
cefSpecialFields = [ 'policy_name', 'rule_name', 'server_platform' ]
eventIdMap = {
    "network service modified": 215,
    "halo logout": 414,
    "daemon compromised": 712,
    "authorized ips modified": 905,
    "server group deleted": 427,
    "configuration policy created": 506,
    "alert profile created": 701,
    "server access scan requested": 812,
    "local account deleted (linux only)": 705,
    "special events policy created": 708,
    "daemon version changed": 713,
    "automatic server access scanning enabled": 802,
    "alert profile modified": 703,
    "daemon self-verification scheduled modfied": 909,
    "file integrity monitoring scan requested": 103,
    "automatic software vulnerability management scan schedule modified": 600,
    "automatic configuration scanning disabled": 501,
    "special events policy deleted": 709,
    "halo backup codes generated": 402,
    "configuration policy deleted": 507,
    "halo login failure": 409,
    "automatic server access scan schedule modified": 800,
    "halo password recovery requested": 400,
    "network service deleted": 213,
    "file integrity object signature changed": 127,
    "file integrity policy assigned": 105,
    "software vulnerability scan exception expired": 605,
    "software vulnerability detected": 603,
    "halo user account unlocked": 423,
    "alert profile unassigned": 704,
    "server missing": 719,
    "halo user account locked": 422,
    "server shutdown": 724,
    "multiple root accounts detected (linux only)": 715,
    "automatic software vulnerability management scanning enabled": 602,
    "local account activation requested": 804,
    "local account created (linux only)": 714,
    "server un-retired": 725,
    "automatic file integrity scan schedule modified": 100,
    "alert profile assigned": 700,
    "api secret key viewed": 904,
    "local account modification requested": 809,
    "halo user deactivated": 912,
    "halo user reactivated": 916,
    "configuration scan requested": 513,
    "api key created": 901,
    "special events policy unassigned": 711,
    "software vulnerability scan exception created": 604,
    "file integrity object missing": 126,
    "file integrity baseline expired": 120,
    "daily status email scheduled modified": 910,
    "ghostports session close": 316,
    "halo password recovery failed": 418,
    "halo password recovery success": 420,
    "halo password changed": 415,
    "api key modified": 903,
    "automatic file integrity scanning enabled": 102,
    "server firewall modified locally": 706,
    "configuration policy exported": 508,
    "halo firewall policy assigned": 201,
    "daemon self-verification scan requested": 401,
    "configuration policy assigned": 505,
    "halo firewall policy deleted": 204,
    "halo user modified": 914,
    "configuration rule matched": 503,
    "file integrity policy deleted": 109,
    "configuration policy imported": 509,
    "software vulnerability scan requested": 606,
    "file integrity policy created": 107,
    "network service added": 211,
    "file integrity baseline failed": 121,
    "daemon heartbeat interval modified": 906,
    "automatic file integrity scanning disabled": 101,
    "file integrity policy unassigned": 113,
    "server retired": 723,
    "file integrity policy imported": 129,
    "alert profile deleted": 702,
    "file integrity policy modified": 111,
    "automatic software vulnerability management scanning disabled": 601,
    "automatic configuration scanning enabled": 502,
    "file integrity policy changed": 133,
    "ghostports expiration time modified": 911,
    "halo firewall policy unassigned": 208,
    "password configuration settings modified": 918,
    "file integrity exception created": 122,
    "ghostports login success": 306,
    "halo login success": 413,
    "server deleted": 717,
    "new server": 716,
    "local account deactivation requested": 808,
    "file integrity baseline": 115,
    "automatic configuration scan schedule modified": 500,
    "halo password recovery request failed": 419,
    "ghostports provisioning": 311,
    "local account creation requested": 806,
    "special events policy assigned": 707,
    "master account linked": 917,
    "server moved to another group": 721,
    "server firewall restore requested": 216,
    "server restarted": 722,
    "halo firewall policy created": 210,
    "daemon self-verification enabled": 908,
    "file integrity exception deleted": 123,
    "server group added": 425,
    "halo user re-invited": 915,
    "ghostports login failure": 305,
    "file integrity object added": 125,
    "api key deleted": 902,
    "file integrity baseline deleted": 119,
    "daemon registration key regenerated": 900,
    "file integrity policy exported": 128,
    "daemon self-verification disabled": 907,
    "local account ssh keys update requested": 811,
    "file integrity exception expired": 124,
    "server ip address changed": 718,
    "halo session timeout": 421,
    "configuration policy unassigned": 512,
    "configuration policy modified": 510,
    "special events policy modified": 710,
    "automatic server access scanning disabled": 801,
    "halo firewall policy modified": 206,
    "file integrity re-baseline": 131,
    "halo user invited": 913,
}


def processCmdLineArgs(argv):
    """ Process the script-specific command line arguments.

        A description of these arguments can be found in the printUsage() function.
    """
    global oneEventPerLine, verbose, outputFormat, outputDestination, lastTimestamp, configDir, syslogInfo
    global redis_host, redis_port, metadataDestination, useHA, apiURL, apiPort
    argsOK = True
    for arg in argv:
        if ((arg == '-?') or (arg == "-h")):
            printUsage(os.path.basename(argv[0]))
            return True
        elif ((arg == '-b') or (arg == '--one-batch-per-line')):
            oneEventPerLine = False
        elif (arg == '-v'):
            verbose = True
        elif (arg.startswith('--starting=')):
            lastTimestamp = arg[11:]
            (ok, error) = cputils.verifyISO8601(lastTimestamp)
            if not ok:
                print >> sys.stderr, error
                return True
        elif (arg.startswith('--auth=')):
            filename = arg[7:]
            if len(authFilenameList) > 0:
                print >> sys.stderr, "Error: Only one auth filename allowed"
                return True
            else:
                authFilenameList.append(filename)
        elif (arg.startswith('--url=')):
            apiURL = arg[6:]
            print >> sys.stderr, "Using URL: %s" % apiURL
        elif (arg.startswith('--port=')):
            apiPort = int(arg[7:])
            print >> sys.stderr, "Using Port: %s" % apiPort
        elif (arg.startswith('--cfgdir=') or arg.startswith('--configdir=')):
            i = arg.index('=') + 1
            configDir = arg[i:]
        elif (arg.startswith('--jsonfile=')):
            outputFormat = 'json-file'
            outputDestination = arg[11:]
        elif (arg.startswith('--ceffile=')):
            outputFormat = 'cef-file'
            outputDestination = arg[10:]
        elif (arg == '--cef'):
            outputFormat = 'cef-file'
            outputDestination = None
        elif (arg.startswith('--cefsyslog')):
            outputFormat = 'cef-syslog'
            outputDestination = 'localhost'
        elif (arg.startswith('--kvfile=')):
            outputFormat = 'kv-file'
            outputDestination = arg[9:]
        elif (arg == '--kv'):
            outputFormat = 'kv-file'
            outputDestination = None
        elif (arg.startswith('--txtsyslog')):
            if (syslogAvailable):
                if (arg.startswith('--txtsyslog=')):
                    outputFormat = 'txt-file'
                    outputDestination = arg[12:]
                else:
                    outputFormat = 'txt-syslog'
                    outputDestination = 'localhost'
            else:
                syslogNotAvailable()
        elif (arg.startswith('--kvsyslog')) and (not isWindows):
            if (syslogAvailable):
                outputFormat = 'kv-syslog'
                outputDestination = 'localhost'
            else:
                syslogNotAvailable()
        elif (arg.startswith('--facility=')):
            combo = arg[11:]
            syslogInfo = combo.split('.')
            valid = True
            if isWindows:
                if not (syslogInfo[0] in remote_syslog.FACILITY):
                    print >> sys.stderr, "%s is not a valid facility" % syslogInfo[0]
                    valid = False
                if not (syslogInfo[1] in remote_syslog.LEVEL):
                    print >> sys.stderr, "%s is not a valid priority/level" % syslogInfo[1]
                    valid = False
            else:
                if not (syslogInfo[0] in cpsyslog.FACILITY):
                    print >> sys.stderr, "%s is not a valid facility" % syslogInfo[0]
                    valid = False
                if not (syslogInfo[1] in cpsyslog.LEVEL):
                    print >> sys.stderr, "%s is not a valid priority/level" % syslogInfo[1]
                    valid = False
            if not valid:
                sys.exit(3)
        elif (arg.startswith('--redis')):
            if redisAvailable:
                if (arg.startswith('--redis=')):
                    tmp_host = arg.split('=')[1]
                    if (not redisFailoverAvailable) and (':' in tmp_host):
                        (redis_host, redis_port) = tmp_host.split(':')
                    else:
                        redis_host = tmp_host
            else:
                print >> sys.stderr, "Redis-py package not available, please install"
                sys.exit(1)
        elif (arg.startswith('--halite')):
            metadataDestination = 'redis'
        elif (arg.startswith('--ha')):
            metadataDestination = 'redis'
            useHA = True
        elif (arg != argv[0]):
            print >> sys.stderr, "Unrecognized argument: %s" % arg
            argsOK = False
    if (metadataDestination == 'redis'):
        if (redis_host == None):
            if (os.path.exists(haConfigFile)):
                (redis_host, redis_port) = readHAConfigFile(haConfigFile)
            if (redis_host != None):
                if verbose:
                    if (redis_port != None):
                        print >> sys.stderr, "Found ha node list: %s:%d" % (redis_host, redis_port)
                    else:
                        print >> sys.stderr, "Found ha node list: %s" % redis_host
            else:
                if (redisFailoverAvailable):
                    srvType = "zookeeper"
                else:
                    srvType = "redis"
                print >> sys.stderr, "If using --ha or --halite, you must specify a %s list using --redis=" % srvType
                return True
    if not argsOK:
        print >> sys.stderr, "Run \"%s -h\" to see usage info." % os.path.basename(argv[0])
        return True
    if (outputFormat == None):
        print >> sys.stderr, "No output type selected, must choose one"
        printUsage(argv[0])
        return True
    else:
        return False


def syslogNotAvailable():
    """ Print error message listing missing modules for syslog functionality.
    """
    print >> sys.stderr, "Syslog functions not available. To enable them, obtain the following module:"
    if (isWindows):
        print >> sys.stderr, "  remote_syslog.py"
    else:
        print >> sys.stderr, "  cpsyslog.py (syslog should be available as part of Python)"
    sys.exit(1)


def openOutput():
    """ Open the socket/file/syslog-connection/whatever to which output is sent.
    """
    global outputFormat, outputDestination, syslogOpen, outfp, fileAppend, syslogInfo
    if (outputFormat.endswith('-syslog')):
        if (not syslogOpen):
            if not isWindows:
                syslogFacility = 'user'
                if (syslogInfo):
                    syslogFacility = syslogInfo[0]
                syslog.openlog('cpapi', 0, cpsyslog.FACILITY[syslogFacility])
            else:
                remote_syslog.openlog()
            syslogOpen = True
    elif (outputFormat.endswith('-file')):
        if ((outfp == None) and (outputDestination != None)):
            if (fileAppend):
                mode = 'a'
            else:
                mode = 'w+'
            outfp = codecs.open(outputDestination, mode, encoding='utf-8')


def processExit():
    """ Handles any tasks which must be done no matter how we exit.

        This code is called no matter how we exit, whether by sys.exit() or
        returning from main body of code. So any code that needs to be executed,
        regardless of why we exit, should be added here.
    """
    global pidFilename, syslogOpen
    try:
        if (syslogOpen):
            if not isWindows:
                syslog.closelog()
            else:
                remote_syslog.closelog()
        if ('redis' == metadataDestination):
            clearRedisLock()
        else:
            os.remove(pidFilename)
    except:
        if (os.path.exists(pidFilename)):
            print >> sys.stderr, "Unable to clean up lock file %s, clean up manually" % pidFilename


def printUsage(progName):
    """ Prints the program usage.

        Lists all accepted command line arguments, and a short description of each one.
    """
    print >> sys.stderr, "Usage: %s [<flag>]... " % progName
    print >> sys.stderr, "Where <flag> is one of:"
    print >> sys.stderr, "-h\t\t\tThis message"
    print >> sys.stderr, "--auth=<file>\t\tSpecify a file containing ID/secret pairs (up to 5)"
    print >> sys.stderr, "--url=<haloURL>\t\tSpecify the base URL for Halo access"
    print >> sys.stderr, "--port=<portNum>\tSpecify the HTTPS port for Halo access"
    print >> sys.stderr, "--starting=<time>\tSpecify start of event time range in ISO-8601 format"
    print >> sys.stderr, "--configdir=<dir>\tSpecify directory for config files (saved timestamps)"
    print >> sys.stderr, "--jsonfile=<filename>\tWrite raw JSON to file with given filename"
    if redisAvailable:
        print >> sys.stderr, "--halite\t\tWrite events normally, but store lock and timestamp info in redis"
        print >> sys.stderr, "--ha\t\t\tWrite events (and store lock and timestamp info) in redis cloud"
        if redisFailoverAvailable:
            print >> sys.stderr, "--redis=zkserver:port[,...]\tSpecify a redis failover cloud"
            print >> sys.stderr, "\t\t\tWhere zkserver:port is a list of Zookeeper nodes"
        else:
            print >> sys.stderr, "--redis[=server[:port]]\tWrite events directly to a redis DB server"
    print >> sys.stderr, "--cef\t\t\tWrite CEF (ArcSight) to standard output (terminal)"
    print >> sys.stderr, "--ceffile=<filename>\tWrite CEF (ArcSight) to file with given filename"
    print >> sys.stderr, "--kv\t\t\tWrite key/value pairs to standard output (terminal)"
    print >> sys.stderr, "--kvfile=<filename>\tWrite key/value pairs to file with given filename"
    if not isWindows:
        if (syslogAvailable):
            print >> sys.stderr, "--txtsyslog\t\tWrite general text to local syslog daemon"
    else:
        if (syslogAvailable):
            print >> sys.stderr, "--txtsyslog[=<file>]\tWrite general text to local syslog daemon or file"
    print >> sys.stderr, "--cefsyslog\t\tWrite CEF (ArcSight) format to local syslog daemon"
    if (syslogAvailable):
        if not isWindows:
            print >> sys.stderr, "--kvsyslog\t\tWrite key/value pairs to local syslog daemon"
    print >> sys.stderr, "--facility=<facility.priority>\tFacility and Priority for syslog entries"
    print >> sys.stderr, "\t\t\t(Above only needed for syslog output options)"
    flist = ""
    llist = ""
    if isWindows:
        for f in sorted(remote_syslog.FACILITY.iterkeys()):
            flist += " %s" % f
        for l in sorted(remote_syslog.LEVEL.iterkeys()):
            llist += " %s" % l
    else:
        for f in sorted(cpsyslog.FACILITY.iterkeys()):
            flist += " %s" % f
        for l in sorted(cpsyslog.LEVEL.iterkeys()):
            llist += " %s" % l
    print >> sys.stderr, "Facilities: %s" % flist
    print >> sys.stderr, "Priorities: %s" % llist
    print >> sys.stderr, "The default event output format is JSON to standard output (terminal)"


def readHAConfigFile(filename):
    server = None
    port = None
    fp = open(filename)
    if (redisFailoverAvailable):
        target = "zk="
    else:
        target = "redis="
    for line in fp.readlines():
        sline = line.strip()
        # print "HA-Config: %s" % sline
        if sline.startswith(target):
            server = sline.split('=')[1]
            if (target == 'redis='):
                (server, port) = server.split(':')
                port = int(port)
    return (server, port)


def processConfigFile(filename):
    """ Process the config file.

        Currently, the only configuration item is the timestamp when the program
        was last run, and thus the earliest possible timestamp of events we should process.
    """
    timestampMap = {}
    if (not os.path.exists(filename)):
        # print >> sys.stderr, "Config file %s not found" % filename
        return timestampMap
    fp = open(filename)
    lines = fp.readlines()
    fp.close()
    for line in lines:
        str = line.strip()
        if not str.startswith("#"):
            fields = str.split("|")
            if (len(fields) == 2):
                timestampMap[fields[0]] = fields[1]
    return timestampMap


def processRedisConfig():
    """ Process the config records in a redis database

        Currently, the only configuration item is the timestamp when the program
        was last run, and thus the earliest possible timestamp of events we should process.
    """
    global redisConnection
    getRedisConnection()
    timestampMap = {}
    accountList = redisConnection.smembers('accounts')
    if (accountList != None):
        for account in accountList:
            key = redisAccountTimePrefix + account
            lastTime = redisConnection.get(key)
            if (lastTime != None):
                timestampMap[account] = lastTime
    return timestampMap


def writeEventString(s):
    """ Write the pre-formatted event to the destination.

        The currently accepted destinations are a file, or a syslog daemon.
    """
    if (s != None):
        if (outputFormat.endswith("-file")):
            if (outfp):
                print >> outfp, s
            else:
                print s
        elif (outputFormat.endswith("-syslog")):
            syslogLevel = 'info'
            if (syslogInfo):
                syslogLevel = syslogInfo[1]
            if not isWindows:
                syslog.syslog(cpsyslog.LEVEL[syslogLevel], s)
            else:
                syslogFacility = 'user'
                if (syslogInfo):
                    syslogFacility = syslogInfo[0]
                remote_syslog.syslog(s, remote_syslog.LEVEL[syslogLevel], remote_syslog.FACILITY[syslogFacility])


def encodeStringAsCEF(str):
    str = str.replace("\\","\\\\")
    str = str.replace("=","\\=")
    str = str.replace("","")
    return str


def formatTimeAsCEF(dt):
    # MMM dd yyyy HH:mm:ss.SSS zzz (note: always formatting as UTC time)
    return dt.strftime("%b %d %Y %H:%M:%S UTC")
    # 5/25/2013 1:04:01 AM PDT
    # return dt.strftime("%m/%d/%Y %I:%M:%S %p UTC")


def writeCustomField(ev,key,customCount,str):
    if (key in ev):
        if (customCount <= 6):
            str += "cs%dLabel=%s cs%d=%s " % (customCount, key, customCount, encodeStringAsCEF(ev[key]))
        customCount += 1
    return (str, customCount)


def convertToCEF(ev):
    global cefVersion, cefVendor, cefProduct, cefProductVersion, cefHeaderList
    str = "CEF:%d|%s|%s|%s|" % (cefVersion, cefVendor, cefProduct, cefProductVersion)
    if ('name' in ev) and (ev['name'].lower() in eventIdMap):
        str += "%s" % eventIdMap[ev['name'].lower()]
    else:
        print >> sys.stderr, "Unable to match event type: %s" % ev['name']
        str += "100" # can't find match, fill in default
    str += "|"
    if ('name' in ev):
        str += "%s" % ev['name']
    severity = 3
    if (('critical' in ev) and (ev['critical'] == "True")):
        severity = 9
    str += "|%d|" % severity
    str += "dvc=%s " % cefHaloGrid # I think this is always true
    # first, do all fields which have a CEF equivalent
    for key in ev:
        if ((not (key in cefHeaderList)) and (not (key in cefSpecialFields)) and (ev[key] != None)):
            if (key in cefFieldMapping):
                value = ev[key]
                if (key == "created_at"):
                    dt = cputils.strToDate(value)
                    value = formatTimeAsCEF(dt)
                str += "%s=%s " % (cefFieldMapping[key], encodeStringAsCEF(value))
    # then, use hueristic to determine "direction"
    if 'actor_username' in ev:
        str += "deviceDirection=0 "
    else:
        str += "deviceDirection=1 "
    # next, some things which are kinda-sorta custom, but need to be assigned to fixed fields, if present
    customCount = 1
    for key in cefSpecialFields:
        (str, customCount) = writeCustomField(ev,key,customCount,str)
    # finally, do all fields which don't have a CEF equivalent
    for key in ev:
        if ((not (key in cefHeaderList)) and (not (key in cefSpecialFields)) and (ev[key] != None)):
            if not (key in cefFieldMapping):
                (str, customCount) = writeCustomField(ev,key,customCount,str)
    if (customCount > 6):
        print sys.stderr, "Found %d custom fields, exceeded 6 allowed" % customCount
    return str


def convertToKV(ev):
    """ Convert an event to list of key=value pairs.

        The value will be surrounded by double-quotes, but the key will be bare.
    """
    str = None
    for key in ev:
        if (str):
            str += " "
        else:
            str = ""
        str += "%s=\"%s\"" % (key, ev[key])
    return str


def convertToTxt(ev):
    """ Convert an event to a reasonably readable English text.

        The main part of the text will be the 'message' field.
        If the 'actor_ip_address' field is present, it will be prepended as "From <ip> - ".
        If the 'created_at' field is present, it will be prepended as "At <time> - ".
    """
    str = ""
    if (outputFormat == "txt-file"):
        str += cputils.getSyslogPrefix()
    if ('created_at' in ev):
        str += "At %s - " % ev['created_at']
    if ('actor_ip_address' in ev):
        str += "From %s - " % ev['actor_ip_address']
    if ('message' in ev):
        str += ev['message']
        for key in ev:
            if not (key in ['created_at', 'actor_ip_address', 'message']):
                str += " %s" % ev[key]
    else:
        #error, don't want to output a broken event
        return None
    return str


def getRedisConnection():
     global redisConnection, redisConnected
     if (not redisConnected):
         if redisFailoverAvailable:
             redisConnection = RedisFailover(hosts=redis_host, zk_path='/redis/cluster', db=0)
         else:
             redisConnection = redis.StrictRedis(host=redis_host, port=redis_port, db=0)
         redisConnected = True


def checkRedisLock():
    global redisConnection, redisLockToken
    getRedisConnection()
    ok = redisConnection.set('locked',redisLockToken, ex=redisLockTimeout, nx=True)
    if (ok == None):
        print >> sys.stderr, "Lock record exists, another process running, exiting"
        sys.exit(1)


def renewRedisLock():
    global redisConnection, redisLockToken
    token = redisConnection.get('locked')
    if (token != None):
        if (token == redisLockToken):
            # lock still active, renew it
            redisConnection.set('locked', redisLockToken, ex=redisLockTimeout)
        else:
            print >> sys.stderr, "Found different lock, another process may be running"
    else:
        # lock expired, but no-one else took it, re-acquire
        print >> sys.stderr, "Warning: lock expired while we were running"
        redisConnection.set('locked', redisLockToken, ex=redisLockTimeout, nx=True)


def clearRedisLock():
    token = redisConnection.get('locked')
    if (token != None):
        if (token == redisLockToken):
            redisConnection.delete('locked')
        else:
            print >> sys.stderr, "Found different lock, another process may be running"
    else:
        print >> sys.stderr, "Warning: lock expired while we were running"


def computeRedisKey(ev):
    return ev['created_at'] + "|" + ev['name'] + "|" + ev['message']


def computeRedisListKey(ev):
    return ev['created_at'].split("T")[0]


def writeToRedis(eventList):
    global redisConnection
    getRedisConnection()
    # for performance, may want to wrap event batch in a transaction
    for ev in eventList:
        redis_key = computeRedisKey(ev)
        redisConnection.set(redis_key,ev)
        list_key = computeRedisListKey(ev)
        redisConnection.sadd(list_key,redis_key)
        redisConnection.sadd(redisUnreadPrefix + list_key,redis_key)
        if not (list_key in redisDateList):
            redisDateList.append(list_key)
            if verbose:
                print >> sys.stderr, "Adding events in Date %s" % list_key


def formatEvents(eventList):
    """ Formats a list of events according to the user's settings.

        We can format in JSON, text, or key-value pairs. Once the
        event is formatted, it's passed to writeEventString() to be
        written to the destination.
    """
    global outputFormat, oneEventPerLine
    if (outputFormat.startswith("json-")):
        if (oneEventPerLine):
            for ev in eventList:
                writeEventString(json.dumps(ev))
        else:
            if (len(eventList) > 0):
                writeEventString(json.dumps(eventList))
    elif (outputFormat == "redis"):
        writeToRedis(eventList)
    elif (outputFormat.startswith("cef-")):
        # in CEF format, always 1-event per line
        for ev in eventList:
            writeEventString(convertToCEF(ev))
    elif (outputFormat.startswith("kv-")):
        for ev in eventList:
            writeEventString(convertToKV(ev))
    elif (outputFormat.startswith("txt-")):
        for ev in eventList:
            writeEventString(convertToTxt(ev))


def dumpEvents(json_str):
    """ Parses a JSON response to the request for an event batch.

        The requests contains an outer wrapper object, with pagination info
        and a list of events. We extract the pagination info (contains a link to
        the next batch of events) and the event list. The event list is passed
        to formatEvents() to be formatted and sent to the desired output.
    """
    timestampKey = 'created_at'
    paginationKey = 'pagination'
    nextKey = 'next'
    eventsKey = 'events'
    obj = json.loads(json_str)
    nextLink = None
    lastTimestamp = None
    if (paginationKey in obj):
        pagination = obj[paginationKey]
        if ((pagination) and (nextKey in pagination)):
            nextLink = pagination[nextKey]
    if (eventsKey in obj):
        eventList = obj[eventsKey]
        if useHA:
            writeToRedis(eventList)
        else:
            formatEvents(eventList)
        numEvents = len(eventList)
        if (numEvents > 0):
            lastEvent = eventList[numEvents - 1]
            if (timestampKey in lastEvent):
                lastTimestamp = lastEvent[timestampKey]
    return (nextLink, lastTimestamp)


def getEventFromRedisKey(r,key):
    resp = r.get(key)
    if (resp == None):
        return None
    else:
        return ast.literal_eval(resp)


def retrieveEventsFromRedis():
    # copied from getEvents.py
    unreadKeys = redisConnection.keys('unread.*')
    # sort unread keys?
    for dirKey in sorted(unreadKeys):
        eventKeyList = redisConnection.smembers(dirKey)
        # sort events?
        for evKey in sorted(eventKeyList):
            if (evKey != None) and (len(evKey) > 0):
                evObj = getEventFromRedisKey(redisConnection,evKey)
                formatEvents([evObj])
                redisConnection.srem(dirKey,evKey)


def writeConfigFile(filename, timestampList):
    """ Writes the configuration file.

        See processConfigFile() for more info.
    """
    try:
        fp = open(filename, "w")
        for entry in timestampList:
            if ('id' in entry) and ('timestamp' in entry):
                fp.write("%s|%s\n" % (entry['id'], entry['timestamp']))
        fp.close()
    except IOError as e:
        print >> sys.stderr, "Failed to save config info to %s" % filename
        print "I/O error({0}): {1}".format(e.errno, e.strerror)
    except:
        print >> sys.stderr, "Failed to save config info to %s" % filename
        print >> sys.stderr, "error: ", sys.exc_info()[0]


def writeRedisConfig(timestampList):
    """ Writes the configuration file.

        See processConfigFile() for more info.
    """
    global redisConnection
    try:
        getRedisConnection()
        for entry in timestampList:
            if ('id' in entry):
                redisConnection.sadd('accounts',entry['id'])
                if ('timestamp' in entry):
                    key = redisAccountTimePrefix + entry['id']
                    redisConnection.set(key,entry['timestamp'])
    except:
        print >> sys.stderr, "Failed to save config info to %s" % filename
        print >> sys.stderr, "error: ", sys.exc_info()[0]


def writeTimestamp(filename, credentialList):
    if ('redis' == metadataDestination):
        writeRedisConfig(credentialList)
    else:
        writeConfigFile(configFilename, credentialList)


def processEventBatches(apiCon,credential,timestampMap,credentialList):
    global shouldExit
    (apiCon.key_id, apiCon.secret) = (credential['id'], credential['secret'])

    # Check that we have a key and secret. Must be obtained either in an auth file,
    #   or on the command-line (not as secure). If we did not find either place, exit.
    if ((not apiCon.key_id) or (not apiCon.secret)):
        print >> sys.stderr, "Unable to read auth file %s. Exiting..." % authFilename
        print >> sys.stderr, "Requires lines of the form \"<API-id>|<secret>\""
        sys.exit(1)

    # Now get beginning timestamp... if not from cmd-line, then from .config file
    if credential['id'] in timestampMap:
        connLastTimestamp = timestampMap[credential['id']]
    else:
        connLastTimestamp = lastTimestamp  # handle timestamp per-connection

    # Now, turn key and secret into an authentication token (usually only good
    #   for 15 minutes or so) by logging in to the REST API server.
    resp = apiCon.authenticateClient()
    if (not resp):
        # no error message here, rely on cpapi.authenticate client for error message
        sys.exit(1)

    # Now, prep the destination for events (open file, or connect to syslog server).
    openOutput()
    # Decide on the initial URL used for fetching events.
    nextLink = apiCon.getInitialLink(connLastTimestamp, events_per_page)

    # Now, enter a "while more events available" loop.
    while (nextLink) and (not shouldExit):
        (batch, authError) = apiCon.getEventBatch(nextLink)
        if (authError):
            # An auth error is likely to happen if our token expires (after 15 minutes or so).
            # If so, we try to renew our session by logging in again (gets a new token).
            resp = apiCon.authenticateClient()
            if (not resp):
                print >> sys.stderr, "Failed to retrieve authentication token. Exiting..."
                sys.exit(1)
        else:
            # If we received a batch of events, send them to the destination.
            (nextLink, connLastTimestamp) = dumpEvents(batch)
            # After each batch, write out config file with latest timestamp (from events),
            #   so that if we get interrupted during the next batch, we can resume from this point.
            credential['timestamp'] = connLastTimestamp
            writeTimestamp(configFilename, credentialList)
            # print "NextLink: %s\t\t%s" % (nextLink, connLastTimestamp)
            # time.sleep(1000) # for testing only
            if (metadataDestination == 'redis'):
                renewRedisLock()

    # only do this if we weren't shut down prematurely
    if (not shouldExit):
        # After we've finished all events, write out current system time
        #   so we don't always re-output the last event (REST API timestamp
        #   comparison is inclusive, so it returns events whose timestamp is
        #   later-than-or-equal-to the provided timestamp).
        connLastTimestamp = cputils.getNowAsISO8601()
        credential['timestamp'] = connLastTimestamp
        writeTimestamp(configFilename, credentialList)


def processAllAccounts(authFilenameList):
    global shouldExit
    if (len(authFilenameList) == 0):
        authFilenameList = [authFilenameDefault]

    apiConnections = []
    for authFilename in authFilenameList:
        if ('redis' == metadataDestination):
            timestampMap = processRedisConfig()
        else:
            configFilename = cputils.convertAuthFilenameToConfig(authFilename)
            configFilename = os.path.join(configDir, configFilename)
            timestampMap = processConfigFile(configFilename)

        # Process the auth file (if any) which contains key and secret
        (credentialList, errMsg) = cputils.processAuthFile(authFilename, progDir)
        if errMsg != None:
            print >> sys.stderr, errMsg
            sys.exit(1)
        # pre-fill timestamps so interim config file writes will at least have saved timestamp
        for credential in credentialList:
            if credential['id'] in timestampMap:
                credential['timestamp'] = timestampMap[credential['id']]

        for credential in credentialList:
            apiCon = cpapi.CPAPI()
            if (apiURL != None):
                apiCon.base_url = apiURL
                if verbose:
                    print >> sys.stderr, "Using URL: %s" % apiCon.base_url
            if (apiPort != None):
                apiCon.port = apiPort
                if verbose:
                    print >> sys.stderr, "Using Port: %s" % apiCon.port
            apiConnections.append(apiCon)
            processEventBatches(apiCon,credential,timestampMap,credentialList)
            if (shouldExit):
                break


class SourceThread(threading.Thread):
    def __init__(self,authFilenameList):
        threading.Thread.__init__(self)
        self.authFilenameList = authFilenameList

    def run(self):
        global shouldExit
        processAllAccounts(self.authFilenameList)
        shouldExit = True


class ConsumerThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        global shouldExit
        while not shouldExit:
            time.sleep(2)
            retrieveEventsFromRedis()
        time.sleep(2)
        retrieveEventsFromRedis()


def interruptHandler(signum, frame):
    global shouldExit
    shouldExit = True
    print >> sys.stderr, "Beginning shutdown..."


def catchCtrlC():
    signal.signal(signal.SIGINT, interruptHandler)
    if verbose:
        print >> sys.stderr, "Registering Ctrl-C handler"

# end of function definitions, begin inline code

atexit.register(processExit)
progDir = os.path.dirname(sys.argv[0])

# Process command-line arguments
if (processCmdLineArgs(sys.argv)):
    sys.exit(0)

if configDir == None:
    configDir = progDir

# Check for other instances of this script running on same host.
if ('redis' == metadataDestination):
    checkRedisLock()
else:
    cputils.checkLockFile(pidFilename)

catchCtrlC()
if (not useHA):
    processAllAccounts(authFilenameList)
else:
    srcThread = SourceThread(authFilenameList)
    dstThread = ConsumerThread()

    srcThread.start()
    dstThread.start()

    while (not shouldExit):
        try:
            time.sleep(1)
        except:
            bob = 7  # need some kind of code here, really just want to ignore

    # srcThread.join()
    # dstThread.join()
