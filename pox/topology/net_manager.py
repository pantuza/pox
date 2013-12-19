# TODO: remove this import
from random import randint


class NetManager(object):

  def __init__(self, graph=None):

    if graph is None:
      raise ValueError("Missing graph argument")

    self.graph = graph

  def linked(self, edge, mst):
    """
    Verifies if an Edge is linked to a vertex in the MST 
    """
    source, destination, weight = edge

    for src, dst, wgh in mst:
      if source in (src, dst) or destination in (src, dst):
        return True
    return False

  def min_edge(self, mst, edges):
    """
    Returns the edge with the minimum weight and that is linked to 
    a vertex in the MST
    """
    if len(edges) > 0:
      min_edge = edges[0]
      WEIGHT = 2

      for edge in edges:
        if self.linked(edge, mst):

          # if there isn't a min_edge or the current edge weight is less than 
          # min_edge weight, then update min_edge with the current edge
          if min_edge is None or edge[WEIGHT] < min_edge[WEIGHT]:
            min_edge = edge

      return min_edge

  def mst(self):
    """ Finds the Minimum Spanning Tree on the graph
    This is implementation is based on Prim algorithm
    using adjacent list
    """

    mst = []
    edges = []
    # Find the edges of the vertexes and insert it in a list
    for vertex in self.graph.vertexes.values():
      for adjacent, edge in vertex.adjacency.items():
        edges.append((vertex, adjacent, edge[0].weight))

    # If the edge list is empty returns an empty Minimum Spanning Tree
    if not edges:
      return mst

    # Minimun Spanning Trees always has |V| - 1 edges. So, we 
    # search for minimum edges until that
    while len(mst) < len(self.graph.vertexes) - 1:
      min_edge = self.min_edge(mst, edges)
      edges.remove(min_edge)
      mst.append(min_edge)

    return mst
