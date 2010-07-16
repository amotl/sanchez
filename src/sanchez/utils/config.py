# -*- coding: utf-8 -*-

class ConfigurationObject(object):

    def __init__(self):
        #self.plugins = []
        pass

    def __setattr__(self, name, value):
        object.__setattr__(self,  name, value)

    def __getattr__(self, name):
        if not self.__dict__.has_key(name):
            setattr(self, name, ConfigurationObject())
        return getattr(self, name)

    def __str__(self):
        # TODO: serialize recursively for nice output
        return str(self.__dict__)

    def __nonzero__(self):
        return bool(self.__dict__)
