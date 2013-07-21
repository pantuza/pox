
class GraphEntity (object):
  
  def __init__ (self, entity):
    self._attrib = {}
    self.entity = entity

  def has(self, key):
    return key in self._attrib

  @property
  def attrib(self, key):
    try:
      return self._attrib[key]
    except KeyError:
      return None

  @attrib.setter
  def attrib(self, key, value):
    try:
      self._attrib[key] = value
      return self._attrib[key]
    except KeyError:
      return None
