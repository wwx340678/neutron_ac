# coding:utf-8

from neutron.restproxy.rest.restclient import RESTClient
from neutron.restproxy.config.configreader import ConfigReader
from neutron.restproxy.config.config import config
from oslo_log import log as logging
import neutron.restproxy.util.dictutil as DictUtil
from neutron.restproxy.restclient import RestClient

import time

OPEN_ID = ''

LOG = logging.getLogger(__name__)


class RESTService(object):

    def __init__(self):

        self.config = self.getConfig()
        self.host = self.config["host"]
        self.port = self.config["port"]
        self.serviceName = self.config["service_name"]
        self.url = "http://" + self.host + ":" + str(self.port)

    def requestREST(self, method, url, id, body={},

                    callBack=None):

        result = {}
        client = RestClient()
        result = client.send(
            self.host, self.port, method, url, self.config["request_timeout"],
            id, body, callBack)
        return result

    def __logOff__(self, data, status, reason):
        self.__requestServiceParams__['success'](data, status, reason)

    def __logoffError__(self, status, reason):
        pass

    def requestService(self, method, url, id, body={}, isNeedServiceName=None,

                       callBack=None):
        Log.debug(('aaaaaaaaaaaaaaaaaaa'))
        result = {}
        client = RESTClient()
        if isNeedServiceName is True:
            for key in body:
                body[key]["serviceName"] = self.serviceName
        self.__requestServiceParams__ = {

                                        "method": method,

                                        "url": self.url + url,

                                        "body": body,

                                        "id": id,

                                        "callBack": callBack

                                        }
        result = self.__doRequestSerive__(data='', status='', reason='')
        if client.httpSuccess(result):
            LOG.debug(('AC:openid is invalid,get openid again.'))
        else:
            if (result['status'] == 200) and result['response']['code'] == 204:
                LOG.debug(('AC:openid is invalid,get openid again.'))

    def __doRequestSerive__(self, data, status, reason):

        result = {}

        result = self.requestREST(
                        self.__requestServiceParams__['method'],

                        self.__requestServiceParams__['url'],

                        self.__requestServiceParams__['id'],

                        self.__requestServiceParams__['body'],

                        self.__requestServiceParams__['callBack'])

        return result

    def __doRequestServiceError__(self, status, reason):

        pass

    def getConfig(self):

        configReader = ConfigReader()
        cfg = configReader.getContent(
            config['config_file_path'] + "config.ini")['opensdk']
        DictUtil.extend(config, cfg)
        return config

    def reportOpenstackName(self):

        openstackInfo = {
                        'neutron_name': self.config['ac_neutron_name'],

                        'neutron_ip': self.config['ac_neutron_ip']

                        }

        body = {
                "neutron_name": self.config['ac_neutron_name'],

                "neutron_ac_data": openstackInfo

                }

        self.requestService(
                        "POST",

                        "/rest/openapi/AgileController/OpenSDK/openstackname",

                        {},

                        body,

                        self.__reportOpenstackNameSuccess__,

                        self.__reportOpenstackNameError__)

    def __reportOpenstackNameSuccess__(self, data, status, reason):
        pass

    def __reportOpenstackNameError__(self, status, reason):

        time.sleep(int(self.config['ac_interval']))

        self.reportOpenstackName()
