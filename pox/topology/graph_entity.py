
class GraphEntity (object):
  
  def __init__ (self, entity):
    self.attrib = {}
    self.entity = entity

  def has(self, key):
    return key in self.attrib

  @property
  def attrib(self, key):
    try:
      return self.attrib[key]
    except KeyError:
      return None

  @attrib.setter
  def attrib(self, key, value):
    try:
      self.attrib[key] = value
      return self.attrib[key]
    except KeyError:
      Return None
