# Copyright 2013 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
A very sloppy IP load balancer.

Run it with --ip=<Service IP> --servers=IP1,IP2,...

Please submit improvements. :)
"""

# Python standard library
import time
import random
import sys
import os


# Pox modules dependencies
from pox.core import core
log = core.getLogger("iplb")

import pox.openflow.libopenflow_01 as of
import pox


# Load Balancing context pox dependencies 
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ethernet import ETHER_BROADCAST
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.util import str_to_bool
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr


# Global definitions
POLICY_NO_LB = 0
POLICY_RANDOM = 1
POLICY_ROUND_ROBIN = 2
POLICY_SERVER_LOAD = 3
POLICY_SERVER_QUEUE = 4
POLICY_SERVER_MIXED = 5
POLICY_DEFAULT = POLICY_ROUND_ROBIN

POLICY_NAME = {}
POLICY_NAME[POLICY_NO_LB] = 'no'
POLICY_NAME[POLICY_RANDOM] = 'random'
POLICY_NAME[POLICY_ROUND_ROBIN] = 'round-robin'
POLICY_NAME[POLICY_SERVER_LOAD] = 'load'
POLICY_NAME[POLICY_SERVER_QUEUE] = 'queue'
POLICY_NAME[POLICY_SERVER_MIXED] = 'mix'

POLICY_NUMBER = {y:x for x,y in POLICY_NAME.iteritems()}

MONITOR_LOAD = 0
MONITOR_QUEUE = 1
MONITOR_LAST_TIME = 2
MONITOR_SEQ = 3

# This block of code has to be updated
# Log file
#MPATH = "/home/mininet/lb"
MPATH = ".."

with open(MPATH+"/pid/lb.pid", "w") as text_file:
  text_file.write(str(os.getpid()))


class MemoryEntry (object):
  """
  Record for flows we are balancing

  Table entries in the switch "remember" flows for a period of time, but
  rather than set their expirations to some long value (potentially leading
  to lots of rules for dead connections), we let them expire from the
  switch relatively quickly and remember them here in the controller for
  longer.

  Another tactic would be to increase the timeouts on the switch and use
  the Nicira extension which can match packets with FIN set to remove them
  when the connection closes.
  """
  
  def __init__ (self, server, first_packet, client_port, ipprot):
    self.server = server
    self.first_packet = first_packet
    self.client_port = client_port
    self.ipprot = ipprot
    self.flow_memory_timeout = 60 * 5
    self.refresh()

  def refresh (self):
    self.timeout = time.time() + self.flow_memory_timeout

  @property
  def is_expired (self):
    return time.time() > self.timeout

  @property
  def key1 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    ipprotp = ethp.find(self.ipprot)

    return ipp.srcip,ipp.dstip,ipprotp.srcport,ipprotp.dstport

  @property
  def key2 (self):
    ethp = self.first_packet
    ipp = ethp.find('ipv4')
    ipprotp = ethp.find(self.ipprot)

    return self.server,ipp.srcip,ipprotp.dstport,ipprotp.srcport


class iplb (object):
  """
  A simple IP load balancer

  Give it a service_ip and a list of server IP addresses.  New TCP flows
  to service_ip will be randomly redirected to one of the servers.

  We probe the servers to see if they're alive by sending them ARPs.
  """
  
  def __init__ (self, connection, service_ip, servers, 
                      policy, logfile, ir,
                      monitor_interval, preview, llp, 
                      ipprot, probe,
                      softtimeout, hardtimeout):
    self.service_ip = IPAddr(service_ip)
    self.servers = [IPAddr(a) for a in servers]
    self.con = connection
    self.mac = self.con.eth_addr
    self.live_servers = {} # IP -> MAC,port
    self.immediate_reverse = ir

    try:
      self.log = log.getChild(dpid_to_str(self.con.dpid))
    except:
      # Be nice to Python 2.6 (ugh)
      self.log = log

    self.outstanding_probes = {} # IP -> expire_time

    # How quickly do we probe?
    self.probe_cycle_time = probe

    # How long do we wait for an ARP reply before we consider a server dead?
    #Erik timeout de 2 para 20
    log.info("Aumentei o arp_timeout de 2 para 20 - Erik")
    self.arp_timeout = 20

    # We remember where we directed flows so that if they start  again,
    # we can send them to the same server if it's still up.  Alternate
    # approach: hashing.
    self.memory = {} # (srcip,dstip,srcport,dstport) -> MemoryEntry

  
    # Preciso de todos os ARPs antes de sondar os servidores


    self._do_probe() # Kick off the probing

    # As part of a gross hack, we now do this from elsewhere
    #self.con.addListeners(self)
    self._start(logfile, policy, monitor_interval, preview, llp, ipprot, softtimeout, hardtimeout)
    self._show_cfg()

  def __del__ (self):
    self._stop()

  def _do_expire (self):
    """
    Expire probes and "memorized" flows

    Each of these should only have a limited lifetime.
    """
    t = time.time()

    # Expire probes
    for ip,expire_at in self.outstanding_probes.items():
      if t > expire_at:
        self.outstanding_probes.pop(ip, None)
        if ip in self.live_servers:
          self.log.warn("Server %s down", ip)
          del self.live_servers[ip]

    # Expire old flows
    c = len(self.memory)
    self.memory = {k:v for k,v in self.memory.items()
                   if not v.is_expired}
    if len(self.memory) != c:
      self.log.debug("Expired %i flows", c-len(self.memory))

  def _do_probe (self):
    """
    Send an ARP to a server to see if it's still up
    """
    self._do_expire()

    server = self.servers.pop(0)
    self.servers.append(server)

    r = arp()
    r.hwtype = r.HW_TYPE_ETHERNET
    r.prototype = r.PROTO_TYPE_IP
    r.opcode = r.REQUEST
    r.hwdst = ETHER_BROADCAST
    r.protodst = server
    r.hwsrc = self.mac
    r.protosrc = self.service_ip
    e = ethernet(type=ethernet.ARP_TYPE, src=self.mac,
                 dst=ETHER_BROADCAST)
    e.set_payload(r)
    #Erik
    #self.log.debug("ARPing for %s", server)
    msg = of.ofp_packet_out()
    msg.data = e.pack()
    msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
    msg.in_port = of.OFPP_NONE
    self.con.send(msg)

    self.outstanding_probes[server] = time.time() + self.arp_timeout

    core.callDelayed(self._probe_wait_time, self._do_probe)

  @property
  def _probe_wait_time (self):
    """
    Time to wait between probes
    """
    r = self.probe_cycle_time / float(len(self.servers))
    #r = max(.25, r) # Cap it at four per second
    #  Alterei para 10 segundos - Aliviar o LinkSys - ERIK
    r = max(10, r) # Cap it at four per second
    #self.log.info("Time???? = " + str(r))
    return r

  def _start(self, logfile, policy, monitor_interval, preview, llp, ipprot, sto, hto):

    self.pkg_in_count = 0
    self.match_ipprot = ipprot
    self.ordered_servers = self.servers[:]
    self.ordered_servers.sort()
    self.set_policy(policy, monitor_interval, preview, llp)
    self.set_timeout(sto, hto)

    self.mpath = MPATH
    self.server_load = {}
    #self.monitor = {}
    #for ip in self.servers:
    #  self.monitor[ip] = open(self.mpath+str(ip)+'.load', 'r')
    self.total_bind_count = 0
    self.pick_count = 0
    self.bind_count = {}
    for ip in self.servers:
      self.bind_count[ip] = 0
    self.logfile = open(self._log_filename(logfile), 'w')
    with open(self.mpath+"/pid/lb.pid", "w") as text_file:
      text_file.write(str(os.getpid()))

  def _show_cfg(self):
    log.info("Server config:")
    log.info("- IP                = " + str(self.service_ip))
    log.info("- IMMEDIATE_REVERSE = " + str(self.immediate_reverse))
    log.info("- POLICY            = " + str(POLICY_NAME[self.policy]))
    log.info("- PREVIEW           = " + str(self.preview_policy))
    log.info("- LAST_LOAD_PREVIEW = " + str(self.last_load_preview))
    log.info("- IP_PROTOCOL       = " + str(self.match_ipprot))
    log.info("- MONITOR_DELAY     = " + str(self.monitoring_interval))
    log.info("- INSTANT_MONITOR   = " + str(self.instant_monitoring))
    log.info("- PROBE_CYCLE_TIME  = " + str(self.probe_cycle_time))
    log.info("- SOFT_TIMEOUT      = " + str(self.flow_idle_timeout))
    log.info("- HARD_TIMEOUT      = " + str(self.flow_hard_timeout))
    log.info("  PATH              = ../dev/pox/pox/misc/ip_loadbalancer")

  def _log_filename(self, logfile):
    if isinstance(logfile, str):
       return self.mpath+'/tmp/'+logfile
    name = self.mpath+'/tmp/lb'
    name += '_'+str(self.service_ip)
    name += '_'+str(self.immediate_reverse)
    name += '_'+str(POLICY_NAME[self.policy])
    name += '_'+str(self.preview_policy)
    name += '_'+str(self.match_ipprot)
    name += '_'+str(self.monitoring_interval)
    name += '_'+str(self.probe_cycle_time)
    name += '_'+str(self.flow_idle_timeout)
    name += '_'+str(self.flow_hard_timeout)
    name += '.txt'
    return name

  def _stop(self):
    #for ip in self.servers:
    #  self.monitor[ip].close()
    self.logfile.close()
    os.remove(self.mpath+"/pid/lb.pid")

  def _monitoring(self):
    self.monitoring_count += 1
    for ip in self.servers:
      self.server_load[ip] = (sys.float_info.max, sys.maxint, sys.float_info.max, sys.maxint)
    for ip in self.live_servers.keys():
      try:
        with open(self.mpath+'/tmp/'+str(ip)+'.monitor', 'r') as mf:
          try:
            line = mf.readline().split()
            self.server_load[ip] = (float(line[MONITOR_LOAD]), 
                                    int(line[MONITOR_QUEUE]), 
                                    float(line[MONITOR_LAST_TIME]),
                                    int(line[MONITOR_SEQ]))
          except:
            self.log.info("Monitoring failure IP = %s  LINE = %s"%(ip, line))
      except:
        self.log.info("Monitoring failure IP = %s. Maybe service/server is down."%(ip))

  def _pick_server (self, key, inport):
    """
    Pick a server for a (hopefully) new connection
    """
    self.pick_count += 1
    if len(self.live_servers) <= 0:
      return None

    if self._monitor:
      if self.instant_monitoring:
        self._monitoring()
      else:
        now = time.time()
        if (now - self.last_monitoring) >= self.monitoring_interval:
          self.last_monitoring = now
          self._monitoring()

    server = self._bind_to(key, inport)

    if server:
      self.total_bind_count += 1
      self.bind_count[server] += 1

    return server

  def _policy_round_robin(self, key, inport):
      tries = 0
      num_servers = len(self.ordered_servers)
      while tries < num_servers:
        ip = self.ordered_servers[self.next_server]
        self.next_server += 1
        if self.next_server >= num_servers:
           self.next_server = 0
        if ip in self.live_servers.keys():
          return ip
      return None

  def _min(self, o, i):
     if len(o) <= 0:
       return None
     ip = o.keys()[0]
     r = o[ip][i]
     for k in o:
       if o[k][i] < r:
         r = o[k][i]
         ip = k
       elif o[k][i] == r and ip > k:
         ip = k
     return ip
     
  def _policy_server_mix(self, key, inport):
      ip = min(self.server_load, key=self.server_load.get)
      if self.preview_policy:
          self._policy_preview(ip)
      return ip

  def _policy_server_load(self, key, inport):
      ip = self._min(self.server_load, MONITOR_LOAD)
      if self.preview_policy:
          self._policy_preview(ip)
      return ip

  def _policy_server_queue(self, key, inport):
      ip = self._min(self.server_load, MONITOR_QUEUE)
      if self.preview_policy:
          self._policy_preview(ip)
      return ip

  def _policy_preview(self, ip):
      cur = self.server_load[ip]
      if self.last_load_preview and self.server_load[ip][MONITOR_LAST_TIME] > 0:
          pl = self.server_load[ip][MONITOR_LAST_TIME]
      else:
          pl = 1
      self.server_load[ip] = (cur[MONITOR_LOAD] + cur[MONITOR_LAST_TIME], 
                              cur[MONITOR_QUEUE] + pl,
                              cur[MONITOR_LAST_TIME], 
                              cur[MONITOR_SEQ] + 1)

  def _policy_random(self, key, inport):
    return random.choice(self.live_servers.keys())

  def policy_no_lb(self, key, inport):
      self.next_server = 0
      return self._policy_round_robin(key, inport)

  def set_timeout(self, sto, hto):
    if not isinstance(sto, float):
      # Mudei de 60.0 para 10.0
      sto = 10.0  
    if sto <= 0:
      sto = 0
    if not isinstance(hto, float):
      hto = of.OFP_FLOW_PERMANENT
    if hto <= 0:
      hto = of.OFP_FLOW_PERMANENT
    
    self.flow_idle_timeout = sto
    self.flow_hard_timeout = hto      


  def set_policy(self, policy, monitor_interval, preview, llp):
    self.policy = policy
    self.monitoring_interval = monitor_interval
    self.last_load_preview = llp
    if monitor_interval > 0.0001:
      self.instant_monitoring = False
      #self.preview_policy = True
    else:
      self.instant_monitoring = True
      #self.preview_policy = False
    self.preview_policy = preview
    self.monitoring_count = 0
    self.last_monitoring = -self.monitoring_interval
    self.next_server = 0
    if policy == POLICY_NO_LB: 
      self._monitor = False
      self._bind_to = self.policy_no_lb
    elif policy == POLICY_RANDOM: 
      self._monitor = False
      self._bind_to = self._policy_random
    elif policy == POLICY_ROUND_ROBIN: 
      self._monitor = False
      self._bind_to = self._policy_round_robin
    elif policy == POLICY_SERVER_LOAD: 
      self._monitor = True
      self._bind_to = self._policy_server_load
    elif policy == POLICY_SERVER_QUEUE: 
      self._monitor = True
      self._bind_to = self._policy_server_queue
    elif policy == POLICY_SERVER_MIXED: 
      self._monitor = True
      self._bind_to = self._policy_server_mix
    else:
      raise Exception("Invalid policy number = %d"%(policy))

  def _handle_PacketIn (self, event):

    self.time = time.time()
    self.pkg_in_count += 1
    inport = event.port
    packet = event.parsed
    self.log.info("PacketIn port = %s", inport)

    def drop ():
      if event.ofp.buffer_id is not None:
        # Kill the buffer
        self.log.info("[%f,%d,%d,%d] Kill the buffer" % (self.time, self.pkg_in_count, self.total_bind_count, self.monitoring_count))
        msg = of.ofp_packet_out(data = event.ofp)
        self.con.send(msg)
      return None

    ipprotp = packet.find(self.match_ipprot)
    if not ipprotp:
      self.log.info("Not " + self.match_ipprot)
      ipp = packet.find('ipv4')
      if not ipp:
        self.log.info("Not IPv4")
      else:
        self.log.info("IPv4 = %s"%ipp)
           
      arpp = packet.find('arp')
      if arpp:
        #Erik
        self.log.info("ARP")
        # Handle replies to our server-liveness probes
        if arpp.opcode == arpp.REPLY:
          if arpp.protosrc in self.outstanding_probes:
            # A server is (still?) up; cool.
            del self.outstanding_probes[arpp.protosrc]
            if (self.live_servers.get(arpp.protosrc, (None,None))
                == (arpp.hwsrc,inport)):
              # Ah, nothing new here.
              pass
            else:
              # Ooh, new server.
              self.live_servers[arpp.protosrc] = arpp.hwsrc,inport
              self.log.info("[%f,%d,%d,%d] Server %s up" % (self.time, self.pkg_in_count, self.total_bind_count, self.monitoring_count, arpp.protosrc))
        return

      # Not TCP and not ARP.  Don't know what to do with this.  Drop it.
      return drop()

    # It's TCP.
    
    ipp = packet.find('ipv4')

    if not self.immediate_reverse and ipp.srcip in self.servers:
      # It's FROM one of our balanced servers.
      # Rewrite it BACK to the client
      #self.log.info("FROM one of our balanced servers.")

      key = ipp.srcip, ipp.dstip, ipprotp.srcport, ipprotp.dstport
      entry = self.memory.get(key)

      if entry is None:
        # We either didn't install it, or we forgot about it.
        self.log.info("[%f,%d,%d,%d] No client for %s" % (self.time,
            self.pkg_in_count, self.total_bind_count, self.monitoring_count, 
            key))
        return drop() 

      # Refresh time timeout and reinstall.
      entry.refresh()

      #self.log.debug("Install reverse flow for %s", key)

      # Install reverse table entry
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_src(self.mac))
      actions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
      actions.append(of.ofp_action_output(port = entry.client_port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=self.flow_idle_timeout,
                            hard_timeout=self.flow_hard_timeout,
                            data=event.ofp,
                            actions=actions,
                            match=match)
      self.con.send(msg)
      log_msg = "[%f,%d,%d,%d] Reverse rule installed from %s:%d to %s:%d"
      self.log.info(log_msg % (self.time, self.pkg_in_count,
          self.total_bind_count, self.monitoring_count, str(ipp.srcip),
          ipprotp.srcport, str(ipp.dstip), ipprotp.dstport))

    elif ipp.dstip == self.service_ip:

      # Ah, it's for our service IP and needs to be load balanced
      #self.log.info("for our service IP")

      ## Do we already know this flow?
      key = ipp.srcip,ipp.dstip,ipprotp.srcport,ipprotp.dstport
      #entry = self.memory.get(key)
      #if entry is None or entry.server not in self.live_servers:

      # Don't know it (hopefully it's new!)
      if len(self.live_servers) == 0:
        self.log.info("[%f,%d,%d,%d] No servers!" % (self.time, 
            self.pkg_in_count, self.total_bind_count, self.monitoring_count))
        return drop() 

      # Pick a server for this flow
      server = self._pick_server(key, inport)
      self.logfile.write("%f;%d;%d;%s;%s\n" % (time.time(), 
          self.total_bind_count, self.monitoring_count, 
          server, str(self.server_load))) 
      if not server:
        self.log.info("[%f,%d,%d,%d] No picked servers!" % (self.time, 
            self.pkg_in_count, self.total_bind_count, self.monitoring_count))
        return drop() 

      entry = MemoryEntry(server, packet, inport, self.match_ipprot)
      self.memory[entry.key1] = entry
      self.memory[entry.key2] = entry
      #else:
      #  self.log.info("%d,%d: Programming last memory traffic to %s -------------------------------", self.total_bind_count, self.monitoring_count, entry.server)
   
      # Update timestamp
      entry.refresh()

      # Set up table entry towards selected server
      mac,port = self.live_servers[entry.server]

      actions = []
      actions.append(of.ofp_action_dl_addr.set_dst(mac))
      actions.append(of.ofp_action_nw_addr.set_dst(entry.server))
      actions.append(of.ofp_action_output(port = port))
      match = of.ofp_match.from_packet(packet, inport)

      msg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                            idle_timeout=self.flow_idle_timeout,
                            hard_timeout=self.flow_hard_timeout,
                            data=event.ofp,
                            actions=actions,
                            match=match)

      if self.immediate_reverse:
        ractions = []
        ractions.append(of.ofp_action_dl_addr.set_src(self.mac))
        ractions.append(of.ofp_action_nw_addr.set_src(self.service_ip))
        ractions.append(of.ofp_action_output(port = inport))
        rmatch = match.flip(port)
        rmatch.dl_src = mac
        rmatch.nw_src = entry.server
        rmsg = of.ofp_flow_mod(command=of.OFPFC_ADD,
                               idle_timeout=self.flow_idle_timeout,
                               hard_timeout=self.flow_hard_timeout,
                               actions=ractions,
                               match=rmatch)
        self.con.send(rmsg)
        self.con.send(msg)
        log_msg = "[%f,%d,%d,%d] Both rules installed "\
                "from %s:%d to %s:%d redirect to %s" 
        self.log.info(log_msg % (self.time, self.pkg_in_count, 
            self.total_bind_count, self.monitoring_count, str(ipp.srcip),
            ipprotp.srcport, str(ipp.dstip), ipprotp.dstport, server))
      else:
        self.con.send(msg)
        log_msg = "[%f,%d,%d,%d] Rule installed "\
                "from %s:%d to %s:%d redirect to %s"
        self.log.info(log_msg % (self.time, self.pkg_in_count, 
            self.total_bind_count, self.monitoring_count, str(ipp.srcip),
            ipprotp.srcport, str(ipp.dstip), ipprotp.dstport, server))


# Remember which DPID we're operating on (first one to connect)
_dpid = None

def launch (ip, servers, policy, logfile, 
            ir = False,
            preview = None,
            llp = None,
            monitor_interval = 4.0, 
            ipprot = 'tcp', 
            probe = 1.0,
            sto = None,
            hto = None):

  servers = servers.replace(","," ").split()
  servers = [IPAddr(x) for x in servers]
  ip = IPAddr(ip)

  if isinstance(monitor_interval, str):
    try:
      monitor_interval = float(monitor_interval)
    except:
      pass
  if (not isinstance(monitor_interval, float)):
    monitor_interval  = 0.0

  if isinstance(preview, str):
    if preview == "True":
      preview = True
    else:
      preview = False
  if (not isinstance(preview, bool)):
    preview = False

  if isinstance(ir, str):
    if ir == "True":
      ir = True
    else:
      ir = False
  if (not isinstance(ir, bool)):
    ir = False  

  if preview:
    if isinstance(llp, str):
      if llp == "True":
        llp = True
      else:
        llp = False
    if (not isinstance(llp, bool)):
      llp = False
  else:
    llp = False
 
  if isinstance(policy, str):
    if policy in POLICY_NUMBER:
      policy = POLICY_NUMBER[policy]
    elif policy.isdigit():
      policy = int(policy)
  if (not isinstance(policy, int)) or ((policy < 0) or (policy >= len(POLICY_NAME))):
    policy = POLICY_ROUND_ROBIN
 
  if isinstance(ipprot, str):
    if ipprot not in ['tcp', 'udp']:
       ipprot = 'tcp'
  if (not isinstance(ipprot, str)):
    ipprot = 'tcp'

  if isinstance(probe, str) or isinstance(probe, int):
    try:
      probe = float(probe)
    except:
      pass
  if (not isinstance(monitor_interval, float)):
    probe  = len(servers)


  # Boot up ARP Responder
  from proto.arp_responder import launch as arp_launch
  arp_launch(eat_packets=False,**{str(ip):True})
  import logging
  logging.getLogger("proto.arp_responder").setLevel(logging.WARN)

  def _handle_ConnectionUp (event):
    global _dpid
    if _dpid is None:
      log.info("IP Load Balancer Ready.")
      core.registerNew(iplb, event.connection, IPAddr(ip), servers, 
              policy, logfile, ir, monitor_interval, preview, 
              llp, ipprot, probe, sto, hto)
      _dpid = event.dpid
      log.info("Datapath Id = %s ", _dpid )

    if _dpid != event.dpid:
      log.warn("Ignoring switch %s", event.connection)
    else:
      log.info("Load Balancing on %s", event.connection)
      #========================================================================
      # For test purpose, clear any configuration in Swicth
      # create ofp_flow_mod message to delete all flows
      # (note that flow_mods match all flows by default)
      msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
 
      event.connection.send(msg)
      log.info("Clearing all flows from %s." % (dpidToStr(event.connection.dpid),))
      #========================================================================
      # Gross hack
      core.iplb.con = event.connection
      event.connection.addListeners(core.iplb)

  core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
