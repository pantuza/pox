

class NetManager(object):

  def __init__(self, graph=None):

    if graph is None:
      raise ValueError("Missing graph argument")

    self.graph = graph

  def mst(self):
    """ Finds the Minimum Spanning Tree on the graph
    This is implementation is based on Prim algorithm
    """
    pass
