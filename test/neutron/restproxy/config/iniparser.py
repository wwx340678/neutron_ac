# coding:utf-8

import ConfigParser


class IniParser(object):

    """docstring for ClassName"""
    def __init__(self):
        super(IniParser, self).__init__()
# self.arg = arg

    def read(self, fileName):
        # 初始化
        cf = ConfigParser.ConfigParser()
        cf.read(fileName)

        # 获得所有的section
        sections = cf.sections()
        print sections
        resultDict = {}
        tmpDict = {}

        for section in sections:
            keys = cf.options(section)

            for key in keys:
                tmpDict[key] = cf.get(section, key)

            resultDict[section] = tmpDict
            tmpDict = {}

        return resultDict
