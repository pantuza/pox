from pox.topology.graph_entity import GraphEntity


class Vertex (GraphEntity):
  
  def __init__ (self, entity):
    super(Vertex, self).__init__(entity)
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
