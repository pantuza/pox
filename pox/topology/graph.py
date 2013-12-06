# -*- coding: utf-8 -*-

from pox.core import core
from pox.openflow import libopenflow_01 as of
from pox.openflow.of_json import flow_stats_to_list
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer

from pox.topology.edge import Edge
from pox.topology.vertex import Vertex


class Graph (object):
  """
  Topology Graph
  """
  
  def __init__ (self):
    self.log = core.getLogger()
    self.vertexes = {}
    self.edges = {}
    self._subscribe()

  def add_vertex (self, entity):
    """
    Add a new Graph Entity (Vertex) to the graph vertixes
    """

    if entity.id not in self.vertexes:
      self.vertexes[entity.id] = Vertex(entity)
  
  def remove_vertex (self, entity):
    """
    Remove a Vertex from Vertexes and remove its edges
    """
    if entity.id in self.vertexes:
      vertex = self.vertexes[entity.id]
      for adj_vertex, links in vertex.adjacency.items():
        for link in links:
          self.remove_edge(link)
      del self.vertexes[entity.id]
  
  def get_vertex (self, id=None):
    """
    Returns a vertex by its id
    """
    
    try:
      return self.vertexes[id]
    except IndexError:
      return None

  def add_edge (self, link, weight=None):
    """
    Add an Edge and insert each vertex of the Edge in the adjacency list 
    of each other
    """
    
    if link.id in self.edges:
      raise Exception("Link ID %s already in graph" % str(link.id))

    edge = Edge(link, weight)
    self.edges[link.id] = edge
    v1 = self.get_vertex(link.entity1.id)
    v2 = self.get_vertex(link.entity2.id)
    
    if v1 and v2:
      v1.add_adjacency(v2, link)
      v2.add_adjacency(v1, link)

  def remove_edge (self, link):
    """
    Removes an Edge and its references inside adjacency list of vertexes 
    """
    
    if link.id not in self.edges:
      raise Exception("Link ID %s is not in graph" % str(link.id))

    del self.edges[link.id]
    v1 = self.get_vertex(link.entity1.id)
    v2 = self.get_vertex(link.entity2.id)
    
    if v1 and v2:
      v1.remove_adjacency(v2)
      v2.remove_adjacency(v1)

  def _subscribe(self):
    """
    Subscribe to POX Core events
    """
    
    if core.hasComponent("topology"):
      core.topology.addListenerByName("SwitchJoin", self._handle_SwitchJoin)
      core.topology.addListenerByName("SwitchLeave", self._handle_SwitchLeave)
      core.topology.addListenerByName("HostJoin", self._handle_HostJoin)
      core.topology.addListenerByName("HostLeave", self._handle_HostLeave)
      core.topology.addListenerByName("LinkJoin", self._handle_LinkJoin)
      core.topology.addListenerByName("LinkLeave", self._handle_LinkLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)
      if core.hasComponent("openflow"):
        core.openflow.addListenerByName("FlowStatsReceived", 
          self._handle_flow_stats)
        core.openflow.addListenerByName("PortStatsReceived", 
          self._handle_port_stats)
        Timer(4, self._handle_timer_stats, recurring = True)

  def _handle_timer_stats(self):
    for connection in core.openflow._connections.values():
      connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
      connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    self.log.info("Sent %i flow/port stats request(s)",
                    len(core.openflow._connections))

  def _handle_flow_stats(self, event):
    stats = flow_stats_to_list(event.stats)
    self.log.info("FlowStatsReceived from %s: %s", 
      dpidToStr(event.connection.dpid), stats)

  def _handle_port_stats(self, event):
    stats = flow_stats_to_list(event.stats)
    self.log.info("PortStatsReceived from %s: %s",
      dpidToStr(event.connection.dpid), stats)

  def _handle_SwitchJoin (self, event):
    """  """
    self.log.info("SwitchJoin id: %s", str(event.switch.id))
    self.add_vertex(event.switch)

    self.log.info(", ".join([str(vertex) for vertex in self.vertexes]))

  def _handle_HostJoin (self, event):
    """  """
    self.log.info("HostJoin id: %s", str(event.host.id))
    self.add_vertex(event.host)

    if event.host.switch is not None:
      switch = self.get_vertex(event.host.switch.id)
      if switch is not None:
        self.add_edge(Link(switch, event.host))
  
#    self.log.info(", ".join([str(vertex) for vertex in self.vertexes]))
    self.log.info(str(self.edges))

  def _handle_SwitchLeave (self, event):
    """  """
    self.log.info("SwitchLeave event")
    self.remove_vertex(event.switch)
    
  def _handle_HostLeave (self, event):
    """  """
    self.log.info("HostLeave event")
    self.remove_vertex(event.host) 

  def _handle_EntityJoin (self, event):
    """  """
    self.log.info("EntityJoin event")
    self.add_vertex(event.entity)
  
  def _handle_EntityLeave (self, event):
    """  """
    self.log.info("EntityLeave event")
    self.remove_vertex(event.entity)

  def _handle_LinkJoin (self, event):
    """  """
    self.log.info("LinkJoin fired")
    self.add_edge(event.link)

  def _handle_LinkLeave (self, event):
    """  """
    self.log.info("LinkLeave fired")
    self.remove_edge(event.link)


def launch ():
  core.registerNew(Graph)
