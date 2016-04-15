import urllib2
import json
import requests
from neutron.restproxy.config.configreader import ConfigReader
from neutron.restproxy.config.config import config
import neutron.restproxy.util.dictutil as DictUtil
from oslo_log import log as logging
import traceback

LOG = logging.getLogger(__name__)
TOKEN_ID = ''
class RestClient(object):
    #初始化，并读取配置文件基础参数
    def __init__(self):
        self.config = self.getConfig()
        self.username = self.config['username']
        self.password = self.config['password']
        self.timeout = float(self.config['ac_request_timeout'])
        self.timeout_retry = int(self.config['ac_timeout_retry'])
        self.token_retry = int(self.config['ac_token_retry'])
    #读取配置文件
    def getConfig(self):
        configReader = ConfigReader()
        cfg = configReader.getContent(config['config_file_path'] + "config.ini")['opensdk']
        DictUtil.extend(config, cfg)
        return config
    #获取tokenid
    def GetTokenId(self, host, port):
        auth_method = 'POST'
        auth_base_url = '/controller/v2/tokens'
        auth_url = "https://" + host + ":" + port + auth_base_url
        auth_headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        rest_info = {
                        "userName": self.username,
                        "password": self.password
                    }
        auth_data = json.dumps(rest_info)
        LOG.debug(_('GetTokenId: Auth request information, method: %s, url: %s, headers: %s, data:%s'),
                  auth_method, auth_url, auth_headers, auth_data)
        ret = self.process_request(auth_method, auth_url, auth_headers, auth_data)
        if ( "Timeout Exceptions" == ret ) or ( "Exceptions" == ret ):
            return ''

        LOG.debug(_('GetTokenId: Auth request result, status_code: %s, headers: %s'),
                  ret.status_code, ret.headers)

        if (int(ret.status_code) >= 200 and int(ret.status_code) < 300):
            res_data = eval(ret.content.decode('utf-8'))
            result_data = res_data['data']
            if result_data:
                token_id = result_data['token_id']
                if token_id:
                    LOG.debug(_('AC:Get tokenID successful, token_id is : %s' % token_id))
                    return token_id
        else:
            LOG.error(_('AC:Get tokenID failed'))
            return ''

    #信息发送
    def send(self, host, port, method, url, timeout_ac,id,body={},callBack=None):

        result = {}
        response = None

        if method.upper() == 'GET' or method.upper() == 'DELETE' or method.upper() == 'PUT':
            url = url + "/" + id
        else:
            pass

        params = json.dumps(body)
#        headers = {"Content-type":"application/json","Accept": "application/json", 'X-ACCESS-TOKEN': TOKEN_ID}
        headers = {"Content-type":"application/json","Accept": "application/json"}

        LOG.debug(_('send: request information, method: %s, url: %s, headers: %s, data:%s'),
                  method, url, headers, params)

        ret = self.process_request(method, url, headers, params)

        if ( "Timeout Exceptions" == ret ) or ( "Exceptions" == ret ):
            LOG.error(_('AC: Request failed, ret: %s' % ret))
            result['response'] = None
            result['status'] = ret.status_code
            result['errorCode'] = None
            result['reason'] = None
            return result

        LOG.debug(_('AC: Request result, status_code: %s, content: %s, headers: %s'),
                   ret.status_code, ret.content.decode('utf-8'), ret.headers)

        res_code = int(ret.status_code)
        res_content = ret.content.decode('utf-8')
        try:
            if ( res_code >= 200 and res_code < 300 ):
                LOG.debug(_('AC process request successfully.'))
                res = self.fixJSON(res_content)
                LOG.debug("send: response body is %s", res)
                if not res_content.strip():
                    LOG.debug("send: response body is empty")
                    result['response'] = None
                    result['status'] = ret.status_code
                    result['errorCode'] = None
                    result['reason'] = None
                else:
                    res1 = json.loads(res)
                    LOG.debug("send: response body is %s", res1)
                    result['response'] = res1['result']
                    result['status'] = ret.status_code
                    result['errorCode'] = res1['errorCode']
                    result['reason'] = res1['errorMsg']
            else:
                LOG.error(_('AC process request failed.'))
                if self.token_retry > 0 and res_code == 401:
                    LOG.debug(_('AC:TokenId expired, get again'))
                    TOKEN_ID = ''
                    self.token_retry -= 1
                    (res_code, res_content) = self.send(method, url, body, success, error)
                else:
                    result['response'] = None
                    result['status'] = ret.status_code
                    result['errorCode'] = None
                    result['reason'] = None
        except Exception,e:
            result['response'] = ''
            result['status'] = ret.status_code
            result['reason'] = -1
            result['errorCode'] = -1
            raise Exception

        if callBack is not None:
            callBack(result['errorCode'], result['reason'],result['status'],result['response'])
        else:
            LOG.debug("call back is null")

        return result

    def process_request(self, method, url, headers, data):
        timeout_retry = self.timeout_retry
        ret = None
        temp_ret = None
        while True:
            try:
                if ( method == 'get' ) or ( method == 'GET' ):
                    ret = requests.request(method, url=url, headers=headers, verify=False, timeout=self.timeout)
                else:
                    ret = requests.request(method, url=url, headers=headers, data=data, verify=False, timeout=self.timeout)
                break

            except requests.exceptions.Timeout:
                temp_ret = "Timeout Exceptions"
                LOG.error(_("Time Out Exception, AC: request Exception, traceback:%s" % traceback.format_exc() ))
                timeout_retry = timeout_retry - 1
                if timeout_retry < 0:
                    ret = "Timeout Exceptions"
                    break

            except Exception:
                LOG.error(_("Exception, AC: request Exception, traceback:%s" % traceback.format_exc() ))
                timeout_retry = timeout_retry - 1
                if timeout_retry < 0:
                    if temp_ret == "Timeout Exceptions":
                        ret = "Timeout Exceptions"
                    else:
                        ret = "Exceptions"
                    break

        if ( "Timeout Exceptions" == ret ) or ( "Exceptions" == ret ):
            LOG.error(_('AC: request failed, ret:%s' % ret))
            return ret

        return ret

    #其它内部使用函数
    def fixJSON(self,str):
        return str.replace(r'"result":null', r'"result":"null"')
#其它内部使用函数
    def httpSuccess(self, http):
        LOG.debug(http)
        status = int(http['status'])
        if (status == 200 or status == 204) and http['reason'] is None:
            return True
        else:
            return False
#其它内部使用函数
    def httpError(self):
        pass

#其它内部使用函数
    def httpTimeout(self):
        pass

#其它内部使用函数
    def post(self):
        pass
