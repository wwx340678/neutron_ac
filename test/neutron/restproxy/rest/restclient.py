# coding:utf-8


import urllib
from neutron.restproxy.service import urllib2_ac
# from neutron.openstack.common import log

# LOG = log.getLogger(__name__)


class RESTClient(object):

    def __init__(self):
        pass

    def send(self, host, port, method, url, timeout_ac,
             header={}, body={},
             success=None, error=None):

        result = {}
        conn = None

        if method.upper() == 'GET' or method.upper() == 'DELETE':
            url = url + "?" + urllib.urlencode(body)
        else:
            header['Content-type'] = 'application/json'
        print "_______restclien_"+url
#         LOG.debug(_("----------the request url is %s.",url))
#         try:
#             conn = httplib.HTTPSConnection(host, port, timeout=int(timeout))
#             conn.request(method, url, urllib.urlencode(body), header)
#
#             response = conn.getresponse()
#             res = response.read()
#             res = self.fixJSON(res)
        request = urllib2_ac.Request(
                      url, data=urllib.urlencode(body), headers=header)
        request.get_method = lambda: method.upper()
        try:
            conn = urllib2_ac.urlopen(request, timeout=int(timeout_ac))
            print "______123"+conn.read()
            print conn.getcode()
#             res = self.fixJSON(conn.read())
            res = conn.read()
            result['response'] = res
            result['status'] = 200
            result['reason'] = 0

        except Exception, e:
            print e
            result['response'] = {}
            result['status'] = -1
            result['reason'] = -1

        finally:
            if conn:
                conn.close()

        if self.httpSuccess(result):
            if success is not None:
                success(result['response'], result['status'], result['reason'])
        else:
            if error is not None:
                error(result['status'], result['reason'])

        return result

    #
    # 修改iEMP返回的JSON数据部规范的问题
    #
    def fixJSON(self, str):

        return str.replace(r'"data":null,', r'"data":"null",')

    #
    # 判断HTTP消息是否成功
    #
    def httpSuccess(self, http):
        status = int(http['status'])
        print status
        if (status == 200 or status == 304) and http['response'] is not None:
            return True
        else:
            return False

    #
    # 判断HTTP消息是否错误
    #
    def httpError(self):
        pass

    #
    # HTTP消息是否超时
    #
    def httpTimeout(self):
        pass

# 跟REST相关的常量
CONSTANTS = {
             "GET_OPNEID_URL": "/rest/openapi/sm/session",
             "LOGOFF_URL": "/rest/openapi/sm/session",
             "GET_OPENID_ERROR": -1,
             "DO_SERVICE_ERROR": -2,
             "LOGOFF_ERROR": -3
             }
