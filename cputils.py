#!/usr/bin/env python

# Module with useful functions for scripts using CloudPassage API

import sys
import platform
import os
import datetime
import os.path
import socket
import re
import json
import cpapi

verbose = False

def checkPythonVersion():
    # This script depends on libraries like json and urllib2 which require 2.6 or 2.7
    #   so test for one of those, and exit if not found.
    pyver = platform.python_version()
    if ((not pyver.startswith('2.6')) and (not pyver.startswith('2.7'))):
        print >> sys.stderr, "Python version %s is not supported, need 2.6.x or 2.7.x" % pyver
        sys.exit(1)


def checkPidRunning(pid):
    if (platform.system() != "Windows"):
        try:
            os.kill(pid, 0)
        except OSError:
            return False
        else:
            return True
    else:
        return True


def checkLockFile(filename):
    pid = str(os.getpid())
    if (os.path.isfile(filename)):
        errMsg = "Lock file (%s) exists" % filename
        pid = file(filename, 'r').readlines()[0].strip()
        if (checkPidRunning(int(pid))):
            print >> sys.stderr, "%s... Exiting" % errMsg
        else:
            print >> sys.stderr, "%s, but PID (%s) not running." % (errMsg, pid)
            print >> sys.stderr, "Deleting stale lock file. Try running script again."
            os.remove(filename)
        sys.exit(1)
    else:
        file(filename, 'w').write(pid)


def convertAuthFilenameToConfig(filename):
    basename = os.path.basename(filename)
    return basename.replace(".auth", ".config")


def processAuthFile(filename, progDir):
    if (not os.path.exists(filename)):
        filename = os.path.join(progDir, filename)
        if (not os.path.exists(filename)):
            return (None, "Auth file %s does not exist" % filename)
    fp = open(filename)
    lines = fp.readlines()
    fp.close()
    credentials = []
    for line in lines:
        str = line.strip()
        if not str.startswith("#"):
            fields = str.split("|")
            if (len(fields) == 2):
                if (len(credentials) < 5):
                    credential = {'id': fields[0], 'secret': fields[1]}
                    credentials.append(credential)
                else:
                    print >> sys.stderr, "Ignoring id=%s, only 5 accounts allowed" % fields[0]
    if (len(credentials) == 0):
        return (None, "Empty auth file, no credentials found in %s" % filename)
    else:
        return (credentials, None)


def strToDate(str):
    # assumes a UTC/ISO8601 date/time string (e.g. "2012-08-12T21:39:40.740301Z")
    return datetime.datetime.strptime( str, "%Y-%m-%dT%H:%M:%S.%fZ" )


def verifyISO8601(tstr):
    if (tstr == None) or (len(tstr) == 0):
        return (False, "Empty timestamp, ISO8601 format required")
    iso_regex = "\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{4})?)?$"
    m = re.match(iso_regex, tstr)
    if (m == None):
        return (False, "Timestamp (%s) does not match ISO8601 format" % tstr)
    return (True, "")


def formatTimeAsISO8601(dt):
    tuple = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, dt.microsecond)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06dZ" % tuple


def getNowAsISO8601():
    return formatTimeAsISO8601(datetime.datetime.utcnow())


def getHostname():
    return socket.gethostname()


monthNames = ["???", "Jan", "Feb", "Mar", "Apr",
              "May", "Jun", "Jul", "Aug", "Sep",
              "Oct", "Nov", "Dec"]


def getSyslogTime():
    now = datetime.datetime.now()
    tuple = (monthNames[now.month], now.day, now.hour, now.minute, now.second)
    return "%s %2d %02d:%02d:%02d" % tuple


# Jan  6 19:05:30 percheron cpapi:
def getSyslogPrefix():
    return "%s %s cpapi: " % (getSyslogTime(), getHostname())


###############################################################
## Parsing/Dumping various CP related endpoints (object types)
###############################################################


def isNullOrNot(obj):
    if obj:
        return "is not null"
    else:
        return "is null"

def parseServer(server):
    name = None
    id = None
    ipAddr = None
    if ('hostname' in server):
        name = server['hostname']
    if ('id' in server):
        id = server['id']
    if ('connecting_ip_address' in server):
        ipAddr = server['connecting_ip_address']
    return (name, id, ipAddr)


def dumpServer(server):
    if verbose:
        (name, id, ipAddr) = parseServer(server)
        print "Server: name=%s ip=%s id=%s" % (name, ipAddr, id)


def parseServerGroup(server):
    name = None
    id = None
    if ('name' in server):
        name = server['name']
    if ('id' in server):
        id = server['id']
    return (name, id)


def dumpServerGroup(server):
    if verbose:
        (name, id) = parseServerGroup(server)
        print "ServerGroup: name=%s id=%s" % (name, id)


def parseFirewallPolicy(server):
    name = None
    id = None
    if ('name' in server):
        name = server['name']
    if ('id' in server):
        id = server['id']
    return (name, id)


def dumpFirewallPolicy(server):
    if verbose:
        (name, id) = parseFirewallPolicy(server)
        print "FirewallPolicy: name=%s id=%s" % (name, id)


def dumpFirewallService(service):
    if verbose:
        (serviceName, serviceID, ports, protocol) = parseFirewallService(service)
        print "FirewallService: name=%s id=%s ports=%s/%s" % (serviceName, id, ports, protocol)


def parseFirewallService(service):
    name = None
    id = None
    ports = None
    protocol = None
    if ('name' in service):
        name = service['name']
    if ('id' in service):
        id = service['id']
    if ('port' in service):
        ports = service['port']
    if ('protocol' in service):
        protocol = service['protocol']
    return (name, id, ports, protocol)


###############################################################
## findOrCreate methods for various endpoints
###############################################################


def findHostByNameOrAddress(apiCon, host):
    resultsList = []
    (response, authError) = apiCon.getServerList()
    if ('servers' in response):
        serverList = response['servers']
        for server in serverList:
            (serverName, serverID, serverIpAddr) = parseServer(server)
            if ((serverName == host) or (serverIpAddr == host)):
                dumpServer(server)
                resultsList.append(serverID)
    return resultsList


def findHostByID(apiCon, host):
    (response, authError) = apiCon.getServerList()
    if ('servers' in response):
        serverList = response['servers']
        for server in serverList:
            (serverName, serverID, serverIpAddr) = parseServer(server)
            if (serverID == host):
                dumpServer(server)
                return server
    return None


def getHostList(apiCon):
    resultsList = []
    (response, authError) = apiCon.getServerList()
    if ('servers' in response):
        return response['servers']
    else:
        return None


def findHostInList(serverList, host):
    for server in serverList:
        (serverName, serverID, serverIpAddr) = parseServer(server)
        if (serverID == host):
            dumpServer(server)
            return server
    return None


def findGroupByName(apiCon, gname):
    (response, authError) = apiCon.getServerGroupList()
    if ('groups' in response):
        groupList = response['groups']
        for group in groupList:
            (groupName, groupID) = parseServerGroup(group)
            if (groupName.lower() == gname.lower()):
                dumpServerGroup(group)
                return group
    return None


def getFirewallPolicyList(apiCon):
    (response, authError) = apiCon.getFirewallPolicyList()
    if ('firewall_policies' in response):
        policyList = response['firewall_policies']
        return policyList
    else:
        return None


def findFirewallPolicyByName(apiCon, fwpName):
    (response, authError) = apiCon.getFirewallPolicyList()
    if ('firewall_policies' in response):
        policyList = response['firewall_policies']
        for policy in policyList:
            (policyName, policyID) = parseFirewallPolicy(policy)
            if (policyName.lower() == fwpName.lower()):
                dumpFirewallPolicy(policy)
                return policyID
    return None


def findFirewallPolicyByID(fwpList, fwpID):
    for policy in fwpList:
        if (policy['id'] == fwpID):
            return policy
    return None


def findFirewallServiceByName(fwsName, serviceList):
    for service in serviceList:
        (serviceName, serviceID, ports, protocol) = parseFirewallService(service)
        if (serviceName.lower() == fwsName.lower()):
            dumpFirewallService(service)
            return serviceID
    return None


def findOrCreateFirewallServices(apiCon, desired_list, svc):
    (response, authError) = getFirewallServiceList(apiCon)
    if ('firewall_services' in response):
        existing_list = response['firewall_services']
        for svc in desired_list:
            id = findFirewallServiceByName(svc['name'],existing_list)
            break
        if id == None:
            (response, authError) = createFirewallService(apiCon,svc)
            if ('firewall_service' in response):
                fwsData = response['firewall_service']
                if ('id' in fwsData):
                    id = fwsData['id']
                    svc['id'] = id
    if id == None:
        print >> sys.stderr, "Failed to create service %s" % svc['name']


def createFirewallServiceObj(name,ports,protocol):
    obj = { 'name': name, 'port': ports, 'protocol': protocol }
    return obj


# when creating windows firewall, add these services to rules
drop_svc_list = [ ]
drop_svc_list.append(createFirewallServiceObj('tcp-patch-1-52','1-52','TCP'))
drop_svc_list.append(createFirewallServiceObj('tcp-patch-54-442','54-442','TCP'))
drop_svc_list.append(createFirewallServiceObj('tcp-patch-444-65535','444-65535','TCP'))
drop_svc_list.append(createFirewallServiceObj('udp-patch-1-52','1-52','UDP'))
drop_svc_list.append(createFirewallServiceObj('udp-patch-54-65535','54-65535','UDP'))
accept_svc_list = [ ]
accept_svc_list.append(createFirewallServiceObj('dns AXFR','53','TCP'))
accept_svc_list.append(createFirewallServiceObj('https','443','TCP'))
accept_svc_list.append(createFirewallServiceObj('dns query','53','UDP'))


def findOrCreateFirewallPolicy(apiCon, policyName, platform):
    desiredFirewallPolicy = findFirewallPolicyByName(apiCon,policyName)
    if not (desiredFirewallPolicy):
        print >> sys.stderr, "No %s quarantine policy found, creating: %s" % (platform, policyName)
        findOrCreateFirewallServices(apiCon,drop_svc_list + accept_svc_list)
        policy = createQuarentineFirewallPolicy(policyName, platform, "quarantine fw policy", drop_svc_list, accept_svc_list)
        (response, authError) = apiCon.createFirewallPolicy(policy)
        if authError:
            print >> sys.stderr, "Firewall Policy Creation FAILED: check that your Halo API key has write priviledges on your account"
            return None
    desiredFirewallPolicy = findFirewallPolicyByName(apiCon,policyName)
    return desiredFirewallPolicy


def checkFwPolicy(group, key, platform, policyList, desiredName):
    if key in group:
        id = group[key]
        policy = findFirewallPolicyByID(policyList, id)
        if (policy) and ('name' in policy):
            if verbose:
                print "%s firewall policy: %s" % (platform, policy['name'])
            return desiredName.lower() == policy['name'].lower()
        else:
            print "%s firewall policy: none" % platform
    return False


def checkGroupFirewallPolicies(group, apiCon, linuxFirewallPolicyName, windowsFirewallPolicyName):
    policyList = getFirewallPolicyList(apiCon)
    linuxOK = checkFwPolicy(group, 'linux_firewall_policy_id', 'linux', policyList, linuxFirewallPolicyName)
    windowsOK = checkFwPolicy(group, 'windows_firewall_policy_id', 'windows', policyList,windowsFirewallPolicyName )
    if not linuxOK:
        newPolicy = findOrCreateFirewallPolicy(apiCon, linuxFirewallPolicyName,'linux')
        apiCon.assignFirewallPolicyToGroup(group['id'], 'linux_firewall_policy_id', newPolicy)
    if not windowsOK:
        newPolicy = findOrCreateFirewallPolicy(apiCon, windowsFirewallPolicyName,'windows')
        apiCon.assignFirewallPolicyToGroup(group['id'], 'windows_firewall_policy_id', newPolicy)


def createFirewallRule(chain, policy, svc = None):
    rule = { "log": False, "active": True }
    rule["chain"] = chain
    rule["action"] = policy
    rule["connection_states"] = None
    rule["firewall_interface"] = None
    rule["firewall_source"] = None
    if svc:
        rule["firewall_service"] = svc["id"]
    else:
        rule["firewall_service"] = None
    return rule


def createQuarentineFirewallPolicy(name, platform, description, drop_svc_list = None, accept_svc_list = None):
    fwPolicy = { "name": name, "platform": platform }
    ruleList = []
    if (platform != "windows"):
        ruleList.append(createFirewallRule("INPUT", "DROP"))
        ruleList.append(createFirewallRule("OUTPUT", "DROP"))
    fwPolicy["firewall_rules"] = ruleList
    fwPolicy["description"] = description
    if (platform == "windows"):
        fwPolicy["log_allowed"] = True;
        fwPolicy["log_dropped"] = True;
        fwPolicy["block_inbound"] = True;
        fwPolicy["block_outbound"] = True;
    return { "firewall_policy": fwPolicy }


def createFirewallService(apiCon,svcObj):
    url = "%s:%d/%s/firewall_services" % (apiCon.base_url, apiCon.port, apiCon.api_ver)
    svcData = { 'firewall_service': svcObj }
    jsonData = json.dumps(svcData)
    # print jsonData # for debugging
    (data, authError) = apiCon.doPostRequest(url, apiCon.authToken, jsonData)
    if (data):
        return (json.loads(data), authError)
    else:
        return (None, authError)


def getFirewallServiceList(apiCon):
    url = "%s:%d/%s/firewall_services/" % (apiCon.base_url, apiCon.port, apiCon.api_ver)
    (data, authError) = apiCon.doGetRequest(url, apiCon.authToken)
    if (data):
        return (json.loads(data), authError)
    else:
        return (None, authError)


def getFirewallZoneList(apiCon):
    url = "%s:%d/%s/firewall_zones/" % (apiCon.base_url, apiCon.port, apiCon.api_ver)
    (data, authError) = apiCon.doGetRequest(url, apiCon.authToken)
    if (data):
        return (json.loads(data), authError)
    else:
        return (None, authError)


def createFirewallZone(apiCon,zoneObj):
    url = "%s:%d/%s/firewall_zones" % (apiCon.base_url, apiCon.port, apiCon.api_ver)
    zoneData = { 'firewall_zone': zoneObj }
    jsonData = json.dumps(zoneData)
    # print jsonData # for debugging
    (data, authError) = apiCon.doPostRequest(url, apiCon.authToken, jsonData)
    if (data):
        return (json.loads(data), authError)
    else:
        return (None, authError)
