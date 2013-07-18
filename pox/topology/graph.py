# -*- coding: utf-8 -*-


from pox.core import core

class GraphEntity (object):
  
  def __init__ (self, entity):
    self.attrib = {}
    self.entity = entity


class Vertex (GraphEntity):
  
  def __init__ (self, entity):
    super.__init__(entity)
    self.adjacency = {}
    
  def add_adjacency (self, vertex, link = None):
    if vertex != self:
      try:
        self.adjacency[vertex].append(link)
      except:
        self.adjacency[vertex] = [link]

  def remove_adjacency (self, vertex, link = None):
    try:
      self.adjacency[vertex].remove(link)
      if (self.adjacency[vertex].count == 0):
        del self.adjacency[vertex]
    except:
      pass


class Edge (GraphEntity):
  
  @staticmethod
  def _make_key (link):
    if link.entity1.id <= link.entity2.id:
      return (link.entity1.id, link.entity2.id)
    else:
      return (link.entity2.id, link.entity1.id)

  def __init__ (self, link):
    super.__init__(link)
    self.key = _make_key(link)


class Graph (object):
  """
  Topology Graph
  """
  
  def __init__ (self):
    self.log = core.getLogger()
    self.vertexes = {}
    self.edges = {}
    self._subscribe()

  def _subscribe (self):
    """  """
    if core.hasComponent("topology"):
      core.topology.addListenerByName("SwitchJoin", self._handle_SwitchJoin)
      core.topology.addListenerByName("SwitchLeave", self._handle_SwitchLeave)
      core.topology.addListenerByName("HostJoin", self._handle_HostJoin)
      core.topology.addListenerByName("HostLeave", self._handle_HostLeave)
      core.topology.addListenerByName("LinkJoin", self._handle_LinkJoin)
      core.topology.addListenerByName("LinkLeave", self._handle_LinkLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)

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

  def add_vertex (self, entity):
    """  """
    if entity.id not in self.vertexes:
      self.vertexes[entity.id] = Vertex(entity)
  
  def remove_vertex (self, entity):
    """  """
    if entity.id in self.vertexes:
      vertex = self.vertexes[entity.id]
      for adj_vertex, links in vertex.adjacency.items():
        for link in links:
          remove_edge(link)
      del self.vertexes[entity.id]
  
  def get_vertex (self, id=None):
    """  """
    try:
      return self.vertexes[id]
    except IndexError:
      return None

  def add_edge (self, link):
    """  """
    if link.id in self.edges:
      raise Exception("Link ID %s already in graph" % str(link.id))

    edge = Edge(link)
    self.edges[link.id] = edge
    v1 = get_vertex(link.entity1.id)
    if v1:
      v1.add_adjacency(v2, link)
    v2 = get_vertex(link.entity2.id)
    if v2:
      v2.add_adjacency(v1, link)

  def remove_edge (self, link):
    """  """
    if link.id not in self.edges:
      raise Exception("Link ID %s is not in graph" % str(link.id))

    del self.edges[link.id]
    v1 = get_vertex(link.entity1.id)
    v2 = get_vertex(link.entity2.id)
    v1.remove_adjacency(v2)
    v2.remove_adjacency(v1)


def launch ():
  core.registerNew(Graph)
