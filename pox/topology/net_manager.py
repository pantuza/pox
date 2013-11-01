

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
    min_edge = None
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
    """

    mst = []
    edges = []

     
