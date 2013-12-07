from pox.topology.graph_entity import GraphEntity


class Vertex (GraphEntity):
  
  def __init__ (self, entity):
    super(Vertex, self).__init__(entity)
    self.adjacency = {}
    
  def add_adjacency (self, vertex, edge=None):
    if vertex != self:
      try:
        self.adjacency[vertex].append(edge)
      except:
        self.adjacency[vertex] = [edge]

  def remove_adjacency (self, vertex, edge=None):
    try:
      self.adjacency[vertex].remove(edge)
      if (self.adjacency[vertex].count == 0):
        del self.adjacency[vertex]
    except:
      pass

  def get_adjacents(self):
    try:
      return [(edge.key[1], edge.weight) for edge in self.adjacency.items()]
    except Exception as e:
      raise e
