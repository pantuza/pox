from pox.topology.graph_entity import GraphEntity


class Edge (GraphEntity):
  
  @staticmethod
  def _make_key (link):
    if link.entity1.id <= link.entity2.id:
      return (link.entity1.id, link.entity2.id)
    else:
      return (link.entity2.id, link.entity1.id)

  def __init__ (self, link, weight=None):
    super(Edge, self).__init__(link)
    self.key = Edge._make_key(link)
    self.weight = None
