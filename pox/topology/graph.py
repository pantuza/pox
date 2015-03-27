# -*- coding: utf-8 -*-

from time import time
from random import randrange
from numpy import array
import pydot
import matplotlib.pyplot as plt

from pox.core import core
from pox.openflow import libopenflow_01 as of
from pox.openflow.of_json import flow_stats_to_list
from pox.lib.util import dpidToStr
from pox.lib.recoco import Timer
from pox.lib.addresses import EthAddr
from pox.topology.edge import Edge
from pox.topology.vertex import Vertex
from pox.topology.topology import Host
from pox.topology.topology import Switch
from pox.topology.topology import Link
from pox.topology.net_manager import NetManager
from networkx import networkx as nx


class Graph (object):
  """
  Topology Graph
  """

  def __init__ (self):
    self.log = core.getLogger()
    self.vertexes = {}
    self.edges = {}
    self._subscribe()
    self.net_manager = NetManager(self)
    self.dot = None

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

      for edges in vertex.adjacency.values():
        for edge in edges:
          self.remove_edge(edge)

      del self.vertexes[entity.id]
      del vertex

  def get_vertex (self, id=None):
    """
    Returns a vertex by its id
    """
    
    try:
      return self.vertexes[id]
    except KeyError:
      return None

  def get_adjacents(self, id=None):
    """
    Returns the adjacent list of a given vertex
    """

    try:
      return self.vertexes[id].get_adjacents()
    except IndexError:
      return None

  def snapshot(self):
    """
    Returns a snapshot of the graph. A tuple of vertices and edges
    """
    return (self.vertexes.keys(),
            [(edge.key[0], edge.key[1], edge.weight) for edge in
              self.edges.items()])

  def get_mst(self):
    """
    Returns the online Minimum Spanning Tree
    """
    return self.net_manager.mst()

  def to_dot(self):
    """
    Return the graph in DOT format
    """
    host_height = 0.2
    host_width = 0.2

    # Creates an undericted graph
    dot = pydot.Dot(graph_type='graph')

    # Creates the edges with weights
    for edge in self.edges.values():
      if isinstance(self.vertexes[edge.key[0]].entity, Host):
        node0 = pydot.Node("Host %s" % edge.key[0], fontsize="10.0")
        node0.set_shape("rect")
        node0.set_height(host_height)
        node0.set_width(host_width)
      elif isinstance(self.vertexes[edge.key[0]].entity, Switch):
        node0 = pydot.Node("Switch %s" % edge.key[0], fontsize="10.0",
            color="blue")
        node0.set_shape("diamond")

      dot.add_node(node0)

      if isinstance(self.vertexes[edge.key[1]].entity, Host):
        node1 = pydot.Node("Host %s" % edge.key[1], fontsize="10.0")
        node1.set_shape("rect")
        node1.set_height(host_height)
        node1.set_width(host_width)

      elif isinstance(self.vertexes[edge.key[1]].entity, Switch):
        node1 = pydot.Node("Switch %s" % edge.key[1], fontsize="10.0",
            color="blue")
        node1.set_shape("diamond")
      
      dot.add_node(node1)

      if edge.weight is not None:
        dotedge = pydot.Edge(node0, node1, label=edge.weight, fontsize="9.0")
      else:
        dotedge = pydot.Edge(node0, node1, label=0, fontsize="9.0")

      dot.add_edge(dotedge)

    self.log.info("Writing graph image with %d nodes and %d edges...", 
                  len(self.vertexes), len(self.edges))
    # writes an image of the graph
    dot.write_png("graph.png")
    dot.write(path="graph.dot", format="raw")
    graph = nx.read_dot("graph.dot")
    nx.write_gexf(graph, "graph.gexf")
    self.dot = dot
    return self.dot

  def to_gexf(self):

    node0, node1 = None, None
    #graph = nx.Graph()
    graph = nx.Graph()
    # Creates the edges with weights
    for edge in self.edges.values():
      entity0 = self.vertexes[edge.key[0]].entity
      entity1 = self.vertexes[edge.key[1]].entity

      if isinstance(entity0, Host):
        node0 = "Host %s" % entity0.mac.toStr().replace(":", "-")
        graph.add_node(node0)
      elif isinstance(entity0, Switch):
        node0 = "Switch %s" % entity0.id
        graph.add_node(node0, color='red', size=200)

      if isinstance(entity1, Host):
        node1 = "Host %s" % entity1.mac.toStr().replace(":", "-")
        graph.add_node(node1)
      elif isinstance(entity1, Switch):
        node1 = "Switch %s" % entity1.id
        graph.add_node(node1, color='red', size=200)
  
      if edge.weight is not None:
        graph.add_edge(node0, node1, weight=edge.weight)
      else:
        graph.add_edge(node0, node1, weight=0)

    # color values
    colors=[node.get('color', 'blue') for node in graph.node.values()]
    sizes = [node.get('size', 50) for node in graph.node.values()]

    nx.draw_graphviz(graph, 
            scale=1, 
            cmap = plt.get_cmap('jet'),
            node_color=colors,
            node_size=sizes,
            with_labels=False,
            width=0.5,
            edge_cmap=plt.cm.Blues)

    nH = len([v for v in self.vertexes.values() if isinstance(v.entity, Host)])
    nS = len([v for v in self.vertexes.values() if isinstance(v.entity, Switch)])
    plt.text(0, 0, "Hosts: %d\nSwitches: %d" %(nH, nS),
             horizontalalignment='left', verticalalignment='top',
             position=(-150,120))

    self.log.info("Writing graph image with %d switches and %d hosts..." % (nS,
        nH))
    plt.draw()
    plt.savefig("graph.png", format="png", dpi=500)
    plt.clf()
    #nx.write_gexf(graph, "graph.gexf")

  def add_edge (self, link, weight=None):
    """
    Add an Edge and insert each vertex of the Edge in the adjacency list 
    of each other
    """
    edge = Edge(link, weight)
    self.edges[edge.key] = edge
    v1 = self.get_vertex(link.entity1.id)
    v2 = self.get_vertex(link.entity2.id)
    
    if v1 and v2:
      v1.add_adjacency(v2, edge)
      v2.add_adjacency(v1, edge)

    #self.net_manager.mst()

  def remove_edge (self, edge):
    """
    Removes an Edge and its references inside adjacency list of vertexes 
    """
    
    if edge.key in self.edges:
      del self.edges[edge.key]

    v1 = self.get_vertex(edge.key[0])
    v2 = self.get_vertex(edge.key[1])
    
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
      #core.topology.addListenerByName("LinkLeave", self._handle_LinkLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)
    
      if core.hasComponent("openflow"):
        core.openflow.addListenerByName("FlowStatsReceived", 
          self._handle_flow_stats)
        core.openflow.addListenerByName("PortStatsReceived", 
          self._handle_port_stats)
      
        #Timer(10, self._handle_timer_stats, recurring = True)
        Timer(20, self.to_gexf, recurring = True)

  def _handle_timer_stats(self):
    for connection in core.openflow._connections.values():
      connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
      connection.send(of.ofp_stats_request(body=of.ofp_port_stats_request()))
    #self.log.info("Sent %i flow/port stats request(s)",
    #                len(core.openflow._connections))

  def _handle_flow_stats(self, event):
    # Ignore this function
    stats = flow_stats_to_list(event.stats)
    for entry in stats:
      host = core.topology.getEntityByID(EthAddr(entry['match']['dl_dst']))
      switch = core.topology.getEntityByID(event.connection.dpid)
      #key = (switch.id, host.id)

      try:
        weight = entry['byte_count'] - self.edges[key].weight
#        self.edges[key].weight = weight if weight > 0 else entry['byte_count']
      except:
        continue

    #self.log.info("FlowStatsReceived from %s: %s", 
    #              dpidToStr(event.connection.dpid), stats)

  def _handle_port_stats(self, event):

    stats = flow_stats_to_list(event.stats)
    control_list = []
    for entry in stats:

      port = entry['port_no']
      for v in self.vertexes.values():
        if isinstance(v.entity, Host):
          if v.entity.switch.id == event.connection.dpid and v.entity.port.number == port:
            
            edge_key = (v.entity.switch.id, v.entity.id)
            nbytes = entry['rx_bytes'] + entry['tx_bytes']
            weight = nbytes - self.edges[edge_key].prev_weight_count
            self.edges[edge_key].weight = weight
            self.edges[edge_key].prev_weight_count = nbytes
            
        
        elif isinstance(v.entity, Switch):
          for edge in self.edges.values():
            if edge.type == Edge.TYPES[1] and v.entity.id == event.connection.dpid:
              nbytes = entry['rx_bytes'] + entry['tx_bytes']
             # if v.entity.id == edge.key[0]:
              try:
                edge_key = (v.entity.id, edge.key[1])
                if edge_key not in control_list:

                  weight = nbytes - self.edges[edge_key].prev_weight_count
                  self.edges[edge_key].weight = weight 
                  self.edges[edge_key].prev_weight_count = nbytes
                  control_list.append(edge_key)
              
              except KeyError:
                continue

#     elif v.entity.id == edge.key[1]:
          #      edge_key = (edge.key[0], v.entity.id)
           #     weight = nbytes - self.edges[edge_key].weight
            #    self.log.info("1 %s -> %d", edge_key, weight)
             #   self.edges[edge_key].weight = weight 

  def _handle_SwitchJoin (self, event):
    """  """
    self.log.info("SwitchJoin id: %s", str(event.switch.id))
    self.add_vertex(event.switch)

  def _handle_HostJoin (self, event):
    """  """
    self.log.info("HostJoin id: %s", event.host.id)
    self.add_vertex(event.host)

    if event.host.switch is not None:
      # Add the unknown switch as a vertex
      if not self.get_vertex(event.host.switch.id):
        self.add_vertex(event.host.switch)

      self.add_edge(Link(event.host.switch, event.host))

  def _handle_SwitchLeave (self, event):
    """  """
    self.log.info("SwitchLeave: %s" % event.entity.id)
    self.remove_vertex(event.entity)
    
  def _handle_HostLeave (self, event):
    """  """
    self.log.info("HostLeave: %s" % event.host.id)
    self.remove_vertex(event.host)

  def _handle_EntityJoin (self, event):
    """  """
    self.log.info("EntityJoin: %s" % event.entity.id)
    self.add_vertex(event.entity)
  
  def _handle_EntityLeave (self, event):
    """  """
    self.log.info("EntityLeave: %s" % event.entity.id)
    self.remove_vertex(event.entity)

  def _handle_LinkJoin (self, event):
    """  """
    
    key0 = (event.link.entity1.id, event.link.entity2.id)
    key1 = (event.link.entity2.id, event.link.entity1.id)

    if key0 in self.edges.keys() or key1 in self.edges.keys():
      return

    link = (event.link.entity1.id, 
            event.link.entity2.id,
            event.link.port1,
            event.link.port2)
    
    self.log.info("LinkJoin: %s - edges: %d" % (str(link), len(self.edges)))
    self.add_edge(event.link)

  def _handle_LinkLeave (self, event):
    """  """
    link = (event.link.entity1.id, event.link.entity2.id)
    self.log.info("LinkLeave: switch %s -- switch %s" % link)
    
    if event.link in self.edges.keys():
      edge = self.edges[event.link]
      self.remove_edge(edge)


def launch ():
  core.registerNew(Graph)
