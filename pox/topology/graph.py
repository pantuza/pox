# -*- coding: utf-8 -*-


from pox.core import core


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

    if core.hasComponent("topology"):
      core.topology.addListenerByName("SwitchJoin", self._handle_SwitchJoin)
      core.topology.addListenerByName("SwitchLeave", self._handle_SwitchLeave)
      core.topology.addListenerByName("HostJoin", self._handle_HostJoin)
      core.topology.addListenerByName("HostLeave", self._handle_HostLeave)
      core.topology.addListenerByName("LinkJoin", self._handle_LinkJoin)
      core.topology.addListenerByName("LinkLeave", self._handle_LinkLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)
      core.topology.addListenerByName("EntityLeave", self._handle_EntityLeave)

    #if core.hasComponent("openflow_discovery"):
    #  core.openflow_discovery.addListenerByName("LinkEvent", 
    #                                            self._handle_LinkEvent)

  def _handle_SwitchJoin (self, event):
    self.log.info("SwitchJoin id: %s", str(event.switch.id))
    self.add_vertex(event.switch)

    self.log.info(", ".join([str(vertex) for vertex in self.vertexes]))

  def _handle_HostJoin (self, event):
    self.log.info("HostJoin id: %s", str(event.host.id))
    self.add_vertex(event.host)

    if event.host.switch is not None:
      switch = self.get_vertex(event.host.switch.id)
      if switch is not None:
        self.add_edge(switch, event.host)
  
#    self.log.info(", ".join([str(vertex) for vertex in self.vertexes]))
    self.log.info(str(self.edges))

  def _handle_SwitchLeave (self, event):
    self.log.info("SwitchLeave event")
    
  def _handle_HostLeave (self, event):
    self.log.info("HostLeave event")

  def _handle_EntityJoin (self, event):
    self.log.info("EntityJoin event")
  
  def _handle_EntityLeave (self, event):
    self.log.info("EntityLeave event")

  def _handle_LinkJoin (self, event):
    self.log.info("LinkJoin fired")

  def _handle_LinkLeave (self, event):
    self.log.info("LinkLeave fired")

  def add_vertex (self, entity):
    
    if entity.id not in self.vertexes:
      self.vertexes[entity.id] = entity
  
  def get_vertex (self, id=None):
    
    try:
      return self.vertexes[id]
    except IndexError:
      return None

  def add_edge (self, switch, host):
    try:
      self.edges[switch.id].append(host.id)
    except KeyError:
      self.edges[switch.id] = []
      self.edges[switch.id].append(host.id)


def launch ():
  core.registerNew(Graph)
