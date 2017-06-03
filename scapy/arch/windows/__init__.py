## This file is part of Scapy
## See http://www.secdev.org/projects/scapy for more informations
## Copyright (C) Philippe Biondi <phil@secdev.org>
## This program is published under a GPLv2 license

"""
Customizations needed to support Microsoft Windows.
"""

import os,re,sys,socket,time, itertools
import subprocess as sp
from glob import glob
from scapy.config import conf,ConfClass
from scapy.error import Scapy_Exception,log_loading,log_runtime
from scapy.utils import atol, itom, inet_aton, inet_ntoa, PcapReader
from scapy.base_classes import Gen, Net, SetGen
import scapy.plist as plist
from scapy.sendrecv import debug, srp1
from scapy.layers.l2 import Ether, ARP
from scapy.data import MTU, ETHER_BROADCAST, ETH_P_ARP

conf.use_winpcapy = True
from scapy.arch import pcapdnet
from scapy.arch.pcapdnet import *

LOOPBACK_NAME="lo0"
WINDOWS = True


def _where(filename, dirs=[], env="PATH"):
    """Find file in current dir or system path"""
    if not isinstance(dirs, list):
        dirs = [dirs]
    if glob(filename):
        return filename
    paths = [os.curdir] + os.environ[env].split(os.path.pathsep) + dirs
    for path in paths:
        for match in glob(os.path.join(path, filename)):
            if match:
                return os.path.normpath(match)
    raise IOError("File not found: %s" % filename)

def win_find_exe(filename, installsubdir=None, env="ProgramFiles"):
    """Find executable in current dir, system path or given ProgramFiles subdir"""
    for fn in [filename, filename+".exe"]:
        try:
            if installsubdir is None:
                path = _where(fn)
            else:
                path = _where(fn, dirs=[os.path.join(os.environ[env], installsubdir)])
        except IOError:
            path = filename
        else:
            break        
    return path


class WinProgPath(ConfClass):
    _default = "<System default>"
    # We try some magic to find the appropriate executables
    pdfreader = win_find_exe("AcroRd32") 
    psreader = win_find_exe("gsview32.exe", "Ghostgum/gsview")
    dot = win_find_exe("dot", "ATT/Graphviz/bin")
    tcpdump = win_find_exe("windump")
    tcpreplay = win_find_exe("tcpreplay")
    display = _default
    hexedit = win_find_exe("hexer")
    wireshark = win_find_exe("wireshark", "wireshark")

conf.prog = WinProgPath()


def _get_dict_from_wmi_raw_object(lines):
    ret_dict = {}
    for i in lines:
        key, value = i.split(':', 1)
        ret_dict[key.strip()] = value.strip()
    return ret_dict


def _get_wmi_objects(class_name, fields, condition=None):
    """Get a WMI object using powershell"""
    where_condition = '| where ' + condition if condition is not None else ''
    ps_command = ['powershell', '-NoProfile', 'Get-WMIObject -class {class_name} {where_condition} | select {select_fields} | fl'.format(
        class_name=class_name,
        where_condition=where_condition, 
        select_fields=', '.join(fields))]
    
    output = sp.check_output(ps_command).decode(errors='replace').strip()
    for raw_object in output.split('\r\n\r\n'):
        yield _get_dict_from_wmi_raw_object(raw_object.split('\r\n'))


class PcapNameNotFoundError(Scapy_Exception):
    pass    


def get_windows_if_list():
    interface_list = []
    for wmi_object in _get_wmi_objects('Win32_NetworkAdapter', 
                                       ['Name', 'InterfaceIndex', 'Description', 'GUID', 'MacAddress'], 
                                       'GUID -ne $null'):
        interface_list.append({
            'name': wmi_object['Name'],
            'win_index': int(wmi_object['InterfaceIndex']),
            'description': wmi_object['Description'],
            'guid': wmi_object['GUID'],
            'mac': wmi_object['MacAddress']
            })

    return interface_list


class NetworkInterface(object):
    """A network interface of your local host"""
    
    def __init__(self, data=None):
        self.name = None
        self.ip = None
        self.mac = None
        self.pcap_name = None
        self.description = None
        self.data = data
        if data is not None:
            self.update(data)
        
    def update(self, data):
        """Update info about network interface according to given dnet dictionary"""
        self.name = data["name"]
        self.description = data['description']
        self.win_index = data['win_index']
        # Other attributes are optional
        if conf.use_winpcapy:
            self._update_pcapdata()
        try:
            self.ip = socket.inet_ntoa(get_if_raw_addr(data['guid']))
        except (KeyError, AttributeError, NameError):
            pass
        try:
            self.mac = data['mac']
        except KeyError:
            pass
    
    def _update_pcapdata(self):
        for i in winpcapy_get_if_list():
            if i.endswith(self.data['guid']):
                self.pcap_name = i
                return

        raise PcapNameNotFoundError
    
    def __repr__(self):
        return "<%s: %s %s %s pcap_name=%s description=%s>" % (self.__class__.__name__,
                     self.name, self.ip, self.mac, self.pcap_name, self.description)

from collections import UserDict

class NetworkInterfaceDict(UserDict):
    """Store information about network interfaces and convert between names""" 
    def load_from_powershell(self):
        for i in get_windows_if_list():
            try:
                interface = NetworkInterface(i)
                self.data[interface.name] = interface
            except (KeyError, PcapNameNotFoundError):
                pass
        if len(self.data) == 0:
            log_loading.warning("No match between your pcap and windows network interfaces found. "
                                "You probably won't be able to send packets. "
                                "Deactivating unneeded interfaces and restarting Scapy might help."
                                "Check your winpcap and powershell installation, and access rights.")
    
    def pcap_name(self, devname):
        """Return pcap device name for given Windows device name."""

        try:
            pcap_name = self.data[devname].pcap_name
        except KeyError:
            raise ValueError("Unknown network interface %r" % devname)
        else:
            return pcap_name
            
    def devname(self, pcap_name):
        """Return Windows device name for given pcap device name."""
        
        for devname, iface in self.items():
            if iface.pcap_name == pcap_name:
                return iface.name
        raise ValueError("Unknown pypcap network interface %r" % pcap_name)
    
    def devname_from_index(self, if_index):
        """Return interface name from interface index"""
        for devname, iface in self.items():
            if iface.win_index == if_index:
                return iface.name
        raise ValueError("Unknown network interface index %r" % if_index)

    def show(self, resolve_mac=True):
        """Print list of available network interfaces in human readable form"""

        print("%s  %s  %s  %s" % ("INDEX".ljust(5), "IFACE".ljust(35), "IP".ljust(15), "MAC"))
        for iface_name in sorted(self.data.keys()):
            dev = self.data[iface_name]
            mac = dev.mac
            if resolve_mac:
                mac = conf.manufdb._resolve_MAC(mac)
            print("%s  %s  %s  %s" % (str(dev.win_index).ljust(5), str(dev.name).ljust(35), str(dev.ip).ljust(15), mac)     )
            
ifaces = NetworkInterfaceDict()
ifaces.load_from_powershell()

def pcap_name(devname):
    """Return pypcap device name for given libdnet/Scapy device name"""  
    try:
        pcap_name = ifaces.pcap_name(devname)
    except ValueError:
        # pcap.pcap() will choose a sensible default for sniffing if iface=None
        pcap_name = None
    return pcap_name            

def devname(pcap_name):
    """Return libdnet/Scapy device name for given pypcap device name"""
    return ifaces.devname(pcap_name)

def devname_from_index(if_index):
    """Return Windows adapter name for given Windows interface index"""
    return ifaces.devname_from_index(if_index)
    
def show_interfaces(resolve_mac=True):
    """Print list of available network interfaces"""
    return ifaces.show(resolve_mac)

try:
    _orig_open_pcap = pcapdnet.open_pcap
    pcapdnet.open_pcap = lambda iface,*args,**kargs: _orig_open_pcap(pcap_name(iface),*args,**kargs)
except AttributeError:
    pass

_orig_get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr
pcapdnet.get_if_raw_hwaddr = lambda iface,*args,**kargs: [ int(i, 16) for i in ifaces[iface].mac.split(':') ]
get_if_raw_hwaddr = pcapdnet.get_if_raw_hwaddr


def count_bits_in_ip(ip):
    return sum([bin(int(i)).count("1") for i in ip.split(".")])


def read_routes():
    routes = []
    for wmi_object in _get_wmi_objects('win32_IP4RouteTable', ['InterfaceIndex', 'Destination', 'Mask', 'NextHop']):
        try:
            iface = devname_from_index(int(wmi_object['InterfaceIndex']))
            addr = ifaces[iface].ip
        except:
            continue
        routes.append((atol(wmi_object['Destination']),
                       itom(count_bits_in_ip(wmi_object['Mask'])),
                       wmi_object['NextHop'],
                       iface,
                       addr))
    return routes


def read_routes6():
    return []

if conf.interactive_shell != 'ipython':
    try:
        __IPYTHON__
    except NameError:
        try:
            import readline
            console = readline.GetOutputFile()
        except (ImportError, AttributeError):
            log_loading.info("Could not get readline console. Will not interpret ANSI color codes.") 
        else:
            conf.readfunc = readline.rl.readline
            orig_stdout = sys.stdout
            sys.stdout = console

def sndrcv(pks, pkt, timeout = 2, inter = 0, verbose=None, chainCC=0, retry=0, multi=0):
    if not isinstance(pkt, Gen):
        pkt = SetGen(pkt)
        
    if verbose is None:
        verbose = conf.verb
    debug.recv = plist.PacketList([],"Unanswered")
    debug.sent = plist.PacketList([],"Sent")
    debug.match = plist.SndRcvList([])
    nbrecv=0
    ans = []
    # do it here to fix random fields, so that parent and child have the same
    all_stimuli = tobesent = [p for p in pkt]
    notans = len(tobesent)

    hsent={}
    for i in tobesent:
        h = i.hashret()
        if h in hsent:
            hsent[h].append(i)
        else:
            hsent[h] = [i]
    if retry < 0:
        retry = -retry
        autostop=retry
    else:
        autostop=0


    while retry >= 0:
        found=0
    
        if timeout < 0:
            timeout = None

        pid=1
        try:
            if WINDOWS or pid == 0:
                try:
                    try:
                        i = 0
                        if verbose:
                            print("Begin emission:")
                        for p in tobesent:
                            pks.send(p)
                            i += 1
                            time.sleep(inter)
                        if verbose:
                            print("Finished to send %i packets." % i)
                    except SystemExit:
                        pass
                    except KeyboardInterrupt:
                        pass
                    except:
                        log_runtime.exception("--- Error sending packets")
                        log_runtime.info("--- Error sending packets")
                finally:
                    try:
                        sent_times = [p.sent_time for p in all_stimuli if p.sent_time]
                    except:
                        pass
            if WINDOWS or pid > 0:
                # Timeout starts after last packet is sent (as in Unix version) 
                if timeout:
                    stoptime = time.time()+timeout
                else:
                    stoptime = 0
                remaintime = None
                # inmask = [pks.ins.fd]
                try:
                    try:
                        while 1:
                            if stoptime:
                                remaintime = stoptime-time.time()
                                if remaintime <= 0:
                                    break
                            r = pks.recv(MTU)
                            if r is None:
                                continue
                            ok = 0
                            h = r.hashret()
                            if h in hsent:
                                hlst = hsent[h]
                                for i in range(len(hlst)):
                                    if r.answers(hlst[i]):
                                        ans.append((hlst[i],r))
                                        if verbose > 1:
                                            os.write(1, b"*")
                                        ok = 1                                
                                        if not multi:
                                            del(hlst[i])
                                            notans -= 1;
                                        else:
                                            if not hasattr(hlst[i], '_answered'):
                                                notans -= 1;
                                            hlst[i]._answered = 1;
                                        break
                            if notans == 0 and not multi:
                                break
                            if not ok:
                                if verbose > 1:
                                    os.write(1, b".")
                                nbrecv += 1
                                if conf.debug_match:
                                    debug.recv.append(r)
                    except KeyboardInterrupt:
                        if chainCC:
                            raise
                finally:
                    if WINDOWS:
                        for p,t in zip(all_stimuli, sent_times):
                            p.sent_time = t
        finally:
            pass

        # remain = reduce(list.__add__, hsent.values(), [])
        remain = list(itertools.chain(*[ i for i in hsent.values() ]))

        if multi:
            #remain = filter(lambda p: not hasattr(p, '_answered'), remain);
            remain = [ p for p in remain if not hasattr(p, '_answered')]
            
        if autostop and len(remain) > 0 and len(remain) != len(tobesent):
            retry = autostop
            
        tobesent = remain
        if len(tobesent) == 0:
            break
        retry -= 1
        
    if conf.debug_match:
        debug.sent=plist.PacketList(remain[:],"Sent")
        debug.match=plist.SndRcvList(ans[:])

    #clean the ans list to delete the field _answered
    if (multi):
        for s,r in ans:
            if hasattr(s, '_answered'):
                del(s._answered)
    
    if verbose:
        print("\nReceived %i packets, got %i answers, remaining %i packets" % (nbrecv+len(ans), len(ans), notans))
    return plist.SndRcvList(ans),plist.PacketList(remain,"Unanswered")


import scapy.sendrecv
scapy.sendrecv.sndrcv = sndrcv

def sniff(count=0, store=1, offline=None, prn = None, lfilter=None, L2socket=None, timeout=None, *arg, **karg):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args) -> list of packets
Select interface to sniff by setting conf.iface. Use show_interfaces() to see interface names.
  count: number of packets to capture. 0 means infinity
  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
offline: pcap file to read packets from, instead of sniffing them
timeout: stop sniffing after a given time (default: None)
L2socket: use the provided L2socket
    """
    c = 0

    if offline is None:
        log_runtime.info('Sniffing on %s' % conf.iface)
        if L2socket is None:
            L2socket = conf.L2listen
        s = L2socket(type=ETH_P_ALL, *arg, **karg)
    else:
        s = PcapReader(offline)

    lst = []
    if timeout is not None:
        stoptime = time.time()+timeout
    remain = None
    while 1:
        try:
            if timeout is not None:
                remain = stoptime-time.time()
                if remain <= 0:
                    break

            try:
                p = s.recv(MTU)
            except PcapTimeoutElapsed:
                continue
            if p is None:
                break
            if lfilter and not lfilter(p):
                continue
            if store:
                lst.append(p)
            c += 1
            if prn:
                r = prn(p)
                if r is not None:
                    print(r)
            if count > 0 and c >= count:
                break
        except KeyboardInterrupt:
            break
    s.close()
    return plist.PacketList(lst,"Sniffed")

import scapy.sendrecv
scapy.sendrecv.sniff = sniff


def _is_virtual_interface(name):
    name = name.lower()
    return 'virtual' in name or 'vmware' in name or 'virtualbox' in name


def get_working_if():
    working_interfaces = _get_wmi_objects('win32_NetworkAdapter', ['Name'], 'NetConnectionStatus -e 2')
    working_interfaces = [i['Name'] for i in working_interfaces if not _is_virtual_interface(i['Name'])]
    if len(working_interfaces) is 0:
        return LOOPBACK_NAME
    return working_interfaces[0]


conf.iface = get_working_if()
