# coding:utf-8
import re
from iniparser import IniParser
from config import config


class ConfigReader(object):

    def __init__(self):
        pass

    #
    # 获取配置文件的内容
    #
    def getContent(self, fileName):
        parser = IniParser()
        dict = parser.read(fileName)
        sdk_config = dict['opensdk']
        sdk_config['checkResult'] = True
        sdk_config['debugInfo'] = []
        sdk_config['url'] = r'https://' + \
            sdk_config['host'] + r':' + sdk_config['port']
        self.checkParameter(sdk_config)

        return dict

    def checkParameter(self, sdk_config):
        """check parameter"""
        result = True
        debugInfo = []

        # check host
        pattern = r'^((\d)|([1-9]\d)|(1(\d){2})|(2[0-4]\d)|(25[0-5]))\
            (\.((\d)|([1-9]\d)|(1(\d){2})|(2[0-4]\d)|(25[0-5]))){3}$'
        if not re.match(pattern, sdk_config['host']):
            debugInfo.append("host error and quit")
            result = False

        # check neutron_ip
        if not re.match(pattern, sdk_config['neutron_ip']):
            debugInfo.append("neutron_ip error and quit")
            result = False

        # check port
        try:
            port = int(sdk_config['ac_port'])
            if port <= 1024 or port > 65535:
                debugInfo.append("port is out of range and set default")
                sdk_config['ac_port'] = config['port']
        except:
            debugInfo.append("port is not a number and set default")
            sdk_config['ac_port'] = config['port']

        # check interval
        try:
            if int(sdk_config['ac_interval']) <= 0:
                debugInfo.append("interval is out of range and set default")
                sdk_config['ac_interval'] = config['interval']
        except:
            debugInfo.append("interval is not a number and set default")
            sdk_config['ac_interval'] = config['interval']

        # check request_timeout
        try:
            if int(sdk_config['ac_request_timeout']) <= 0:
                debugInfo\
                    .append("request_timeout is out of range and set default")
                sdk_config['ac_request_timeout'] = config['request_timeout']
        except:
            debugInfo.append("request_timeout is not a number and set default")
            sdk_config['ac_request_timeout'] = config['request_timeout']

        # check neutron_name
        neutron_name = sdk_config['neutron_name']
        if len(neutron_name) > 32:
            debugInfo.append("neutron_name is more than 32 ")
            result = False
        if (not re.match(r'^[a-zA-Z0-9_]*$', neutron_name)) \
                or neutron_name == '':
            debugInfo.append("neutron_name is illegal ")
            result = False
        if not result:
            debugInfo.append("check parameter error and quit ")

        sdk_config['checkResult'] = result
        sdk_config['debugInfo'] = debugInfo

# if __name__ == "__main__":
#     main('config.ini')
