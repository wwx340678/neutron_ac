# coding:utf-8
'''
Created on 2014-8-3

@author: l00284247
'''


from neutron.restproxy.config.config import config
import os


class Logutil(object):

    def __init__(self):
        self.MAX_NUM = 10
        self.MAX_SIZE = 10 * 1024 * 1024

    def checkSize(self, filename):
        if not self.__checkFileName__(filename):
            return
        return os.path.getsize(config['log_path'] + filename) < self.MAX_SIZE

    def createANewLog(self, filename):

        if not self.__checkFileName__(filename):
            return
        if not self.__checkNum__():
            self.__deleteALog__()
        self.__changeFileName__(filename)
        try:
            f = open(config['log_path'] + filename, 'w')
        finally:
            f.close()

    def __checkNum__(self):
        filelist = os.listdir(config['log_path'])
        count = 0
        for file in filelist:
            try:
                if file[-4:] == '.log' and file[:7] == r'huawei.':
                    count = count + 1
            except:
                pass
        return count < self.MAX_NUM

    def __deleteALog__(self):
        path = config['log_path']
        filelist = os.listdir(path)
        filelist.sort(
                        key=lambda fn: os.path.getmtime(path + fn)
                        if not os.path.isdir(path + fn) else 0)
        for file in filelist:
            try:
                if file[-4:] == '.log' and file[:7] == r'huawei.':
                    os.remove(path + file)
                    break
            except:
                pass

    def __checkFileName__(self, filename):
        return os.path.exists(config['log_path'] + filename)

    def __changeFileName__(self, filename):
        if not self.__checkFileName__(filename):
            return
        i = 0
        while i <= 100:
            newname = filename[:-4] + r'.' + str(i) + filename[-4:]
            if not self.__checkFileName__(newname):
                os.rename(
                        config['log_path'] + filename,
                        config['log_path'] + newname)
                break
            i = i + 1

# if __name__ == "__main__":
    # print Logutil().checkSize('rest_proxy.log')
    