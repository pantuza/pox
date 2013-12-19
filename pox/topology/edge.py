from pox.topology.graph_entity import GraphEntity
from pox.topology.topology import Switch
from pox.topology.topology import Host


class Edge (GraphEntity):
  
  TYPES = ['host to switch', 'switch to switch']

  def __init__ (self, link, weight=0):
    super(Edge, self).__init__(link)
    self.type = self.TYPES[0]
    self.key = self._make_key(link)
    self.weight = weight if weight is not None else 0
    self.prev_weight_count = 0

  def _make_key (self, link):

    # both are switches
    if isinstance(link.entity1, Switch) and isinstance(link.entity2, Switch):
      
      self.type = self.TYPES[1]
      
      if link.entity1.id <= link.entity2.id:
        return (link.entity1.id, link.entity2.id)
      else:
        return (link.entity2.id, link.entity1.id)

    # one is a host. Always return the switch as first element of the tuple
    elif isinstance(link.entity1, Host):
      return (link.entity2.id, link.entity1.id)
    else:
      return (link.entity1.id, link.entity2.id)
