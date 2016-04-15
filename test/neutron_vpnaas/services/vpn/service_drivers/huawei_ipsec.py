# Copyright 2015, Nachi Ueno, NTT I3, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import json
from oslo_log import log as logging

from neutron_vpnaas.services.vpn.service_drivers import ipsec
from neutron.restproxy.service.service import RESTService


LOG = logging.getLogger(__name__)

IPSEC = 'ipsec'
BASE_IPSEC_VERSION = '1.0'


class HuaweiIPsecVPNDriver(ipsec.IPsecVPNDriver):
    """VPN Service Driver class for IPsec."""
    flag = True

    def __init__(self, service_plugin):
        super(HuaweiIPsecVPNDriver, self).__init__(service_plugin)

    def create_ikepolicy(self, context, ikepolicy):
        LOG.debug(("create_ikepolicy the ikepolicy is %s."),
                  ikepolicy)
        ikepolicyInfo = self.__setIkepolicyInfo(ikepolicy)
        operation = OperationType.CREATE_IKEPOLICY
        self.__restRequest__("", ikepolicyInfo, operation)

    def delete_ikepolicy(self, context, ikepolicy):
        LOG.debug(("delete_ikepolicy the ikepolicy is %s."),
                  ikepolicy)
        ikepolicyInfo = self.__setIkepolicyInfo(ikepolicy)
        operation = OperationType.DELETE_IKEPOLICY
        self.__restRequest__(ikepolicyInfo['ikepolicy']['id'], {}, operation)

    def update_ikepolicy(self, context, old_ikepolicy, ikepolicy):
        LOG.debug(("update_ikepolicy the ikepolicy is %s."),
                  ikepolicy)
        ikepolicyInfo = self.__setIkepolicyInfo(ikepolicy)
        operation = OperationType.UPDATE_IKEPOLICY
        self.__restRequest__(ikepolicyInfo['ikepolicy']['id'], ikepolicyInfo,
                             operation)

    def create_ipsecpolicy(self, context, ipsecpolicy):
        LOG.debug(("create_ipsecpolicy the ipsecpolicy is %s."),
                  ipsecpolicy)
        ipsecpolicyInfo = self.__setIpsecpolicyInfo(ipsecpolicy)
        operation = OperationType.CREATE_IPSECPOLICY
        self.__restRequest__("", ipsecpolicyInfo, operation)

    def delete_ipsecpolicy(self, context, ipsecpolicy):
        LOG.debug(("delete_ipsecpolicy the ipsecpolicy is %s."),
                  ipsecpolicy)
        ipsecpolicyInfo = self.__setIpsecpolicyInfo(ipsecpolicy)
        operation = OperationType.DELETE_IPSECPOLICY
        self.__restRequest__(ipsecpolicyInfo['ipsecpolicy']['id'], {},
                             operation)

    def update_ipsecpolicy(self, context, old_ipsec_policy, ipsecpolicy):
        LOG.debug(("update_ipsecpolicy the ipsecpolicy is %s."),
                  ipsecpolicy)
        ipsecpolicyInfo = self.__setIpsecpolicyInfo(ipsecpolicy)
        operation = OperationType.UPDATE_IPSECPOLICY
        self.__restRequest__(ipsecpolicyInfo['ipsecpolicy']['id'],
                             ipsecpolicyInfo, operation)

    def create_vpnservice(self, context, vpnservice):
        LOG.debug(("create_vpnservice the vpnservice is %s."),
                  vpnservice)
        vpnserviceInfo = self.__setVpnserviceInfo(vpnservice)
        operation = OperationType.CREATE_VPNSERVICE
        self.__restRequest__("", vpnserviceInfo, operation)

    def update_vpnservice(self, context, old_vpnservice, vpnservice):
        # self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])
        LOG.debug(("update_vpnservice the vpnservice is %s."),
                  vpnservice)
        vpnserviceInfo = self.__setVpnserviceInfo(vpnservice)
        operation = OperationType.UPDATE_VPNSERVICE
        self.__restRequest__(vpnserviceInfo['vpnservice']['id'],
                             vpnserviceInfo, operation)

    def delete_vpnservice(self, context, vpnservice):
        #  self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])
        LOG.debug(("delete_vpnservice the vpnservice is %s."),
                  vpnservice)
        vpnserviceInfo = self.__setVpnserviceInfo(vpnservice)
        operation = OperationType.DELETE_VPNSERVICE
        self.__restRequest__(vpnserviceInfo['vpnservice']['id'], {}, operation)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        # vpnservice = self.service_plugin._get_vpnservice(
        # context, ipsec_site_connection['vpnservice_id'])
        # self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])
        LOG.debug(("create_ipsec_site_connection the ipsec_site_connection \
        is %s."), ipsec_site_connection)
        ipsec_site_connectionInfo = self.__setIpsec_site_connection(
            ipsec_site_connection)
        operation = OperationType.CREATE_IPSEC_SITE_CONNECTION
        self.__restRequest__("", ipsec_site_connectionInfo, operation)

    def update_ipsec_site_connection(
            self, context, old_ipsec_site_connection, ipsec_site_connection):
        # vpnservice = self.service_plugin._get_vpnservice(
        # context, ipsec_site_connection['vpnservice_id'])
        # self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])
        LOG.debug(("update_ipsec_site_connection the ipsec_site_connection \
         is %s."), ipsec_site_connection)
        ipsec_site_connectionInfo = self.__setIpsec_site_connection(
            ipsec_site_connection)
        operation = OperationType.UPDATE_IPSEC_SITE_CONNECTION
        self.__restRequest__(ipsec_site_connectionInfo
                             ['ipsecsiteconn']['id'],
                             ipsec_site_connectionInfo, operation)

    def delete_ipsec_site_connection(self, context, ipsec_site_connection):
        # vpnservice = self.service_plugin._get_vpnservice(
        # context, ipsec_site_connection['vpnservice_id'])
        # self.agent_rpc.vpnservice_updated(context, vpnservice['router_id'])
        LOG.debug(("delete_ipsec_site_connectionthe ipsec_site_connection \
         is %s."), ipsec_site_connection)
        ipsec_site_connectionInfo = self.__setIpsec_site_connection(
            ipsec_site_connection)
        operation = OperationType.DELETE_IPSEC_SITE_CONNECTION
        self.__restRequest__(ipsec_site_connectionInfo['ipsecsiteconn']
                             ['id'], {}, operation)

    def __setIkepolicyInfo(self, ikepolicy):
        ikepolicyInfo0 = {}
        ikepolicyInfo1 = {}
        ikepolicyInfo2 = {}
        ikepolicyInfo1['encryptionAlgorithm'] = \
            ikepolicy['encryption_algorithm']
        ikepolicyInfo1['id'] = ikepolicy['id']
        ikepolicyInfo1['tenantId'] = ikepolicy['tenant_id']
        ikepolicyInfo1['name'] = ikepolicy['name']
        ikepolicyInfo1['description'] = ikepolicy['description']
        ikepolicyInfo1['shared'] = 'false'
        ikepolicyInfo1['authAlgorithm'] = ikepolicy['auth_algorithm']
        ikepolicyInfo1['phase1NegotiationMode'] = \
            ikepolicy['phase1_negotiation_mode']
        ikepolicyInfo1['pfs'] = ikepolicy['pfs']
        ikepolicyInfo1['ikeVersion'] = ikepolicy['ike_version']
        ikepolicyInfo1['servicename'] = ''
        ikepolicyInfo2['units'] = ikepolicy['lifetime']['units']
        ikepolicyInfo2['value'] = ikepolicy['lifetime']['value']
        ikepolicyInfo1['lifetime'] = ikepolicyInfo2
        ikepolicyInfo0['ikepolicy'] = ikepolicyInfo1
        LOG.debug(("the request ikepolicy is %s"), ikepolicyInfo0)
        return ikepolicyInfo0

    def __setIpsecpolicyInfo(self, ipsecpolicy):
        ipsecpolicyInfo0 = {}
        ipsecpolicyInfo1 = {}
        ipsecpolicyInfo2 = {}
        ipsecpolicyInfo1['id'] = ipsecpolicy['id']
        ipsecpolicyInfo1['tenantId'] = ipsecpolicy['tenant_id']
        ipsecpolicyInfo1['name'] = ipsecpolicy['name']
        ipsecpolicyInfo1['description'] = ipsecpolicy['description']
        ipsecpolicyInfo1['shared'] = 'false'
        ipsecpolicyInfo1['transformProtocol'] = \
            ipsecpolicy['transform_protocol']
        ipsecpolicyInfo1['encapsulationMode'] = \
            ipsecpolicy['encapsulation_mode']
        ipsecpolicyInfo1['authAlgorithm'] = ipsecpolicy['auth_algorithm']
        ipsecpolicyInfo1['encryptionAlgorithm'] = \
            ipsecpolicy['encryption_algorithm']
        ipsecpolicyInfo1['pfs'] = ipsecpolicy['pfs']
        ipsecpolicyInfo1['servicename'] = ''
        ipsecpolicyInfo2['units'] = ipsecpolicy['lifetime']['units']
        ipsecpolicyInfo2['value'] = ipsecpolicy['lifetime']['value']
        ipsecpolicyInfo1['lifetime'] = ipsecpolicyInfo2
        ipsecpolicyInfo0['ipsecpolicy'] = ipsecpolicyInfo1
        LOG.debug(("the request ipsecpolicy is %s"),
                  ipsecpolicyInfo0)
        return ipsecpolicyInfo0

    def __setVpnserviceInfo(self, vpnservice):
        vpnserviceInfo0 = {}
        vpnserviceInfo1 = {}
        vpnserviceInfo1['id'] = vpnservice['id']
        vpnserviceInfo1['tenantId'] = vpnservice['tenant_id']
        vpnserviceInfo1['name'] = vpnservice['name']
        vpnserviceInfo1['description'] = vpnservice['description']
        # vpnserviceInfo1['localAddress'] = ''
        subnetIds = []
        subnetIds.append(vpnservice['subnet_id'])
        vpnserviceInfo1['subnetIds'] = subnetIds
        vpnserviceInfo1['routerId'] = vpnservice['router_id']
        vpnserviceInfo1['status'] = vpnservice['status']
        vpnserviceInfo1['adminStateUp'] = vpnservice['admin_state_up']
        vpnserviceInfo1['servicename'] = ''
        vpnserviceInfo0['vpnservice'] = vpnserviceInfo1
        LOG.debug(("the request vpnservice is %s"),
                  vpnserviceInfo0)
        return vpnserviceInfo0

    def __setIpsec_site_connection(self, ipsec_site_connection):
        ipsec_site_connectionInfo1 = {}
        ipsec_site_connectionInfo0 = {}
        ipsec_site_connectionInfo1['id'] = ipsec_site_connection['id']
        ipsec_site_connectionInfo1['tenantId'] = \
            ipsec_site_connection['tenant_id']
        ipsec_site_connectionInfo1['name'] = ipsec_site_connection['name']
        ipsec_site_connectionInfo1['description'] = \
            ipsec_site_connection['description']
        ipsec_site_connectionInfo1['peerAddress'] = \
            ipsec_site_connection['peer_address']
        ipsec_site_connectionInfo1['peerId'] = ipsec_site_connection['peer_id']
        peer_cidrs = []
        for cidr in ipsec_site_connection['peer_cidrs']:
            peer_cidrs.append(cidr)
        ipsec_site_connectionInfo1['peerCidrs'] = peer_cidrs
        ipsec_site_connectionInfo1['routeMode'] = \
            ipsec_site_connection['route_mode']
        ipsec_site_connectionInfo1['mtu'] = ipsec_site_connection['mtu']
        ipsec_site_connectionInfo1['authMode'] = \
            ipsec_site_connection['auth_mode']
        ipsec_site_connectionInfo1['psk'] = ipsec_site_connection['psk']
        ipsec_site_connectionInfo1['initiator'] = \
            ipsec_site_connection['initiator']
        ipsec_site_connectionInfo1['adminStateUp'] = \
            ipsec_site_connection['admin_state_up']
        ipsec_site_connectionInfo1['status'] = ipsec_site_connection['status']
        ipsec_site_connectionInfo1['ikepolicyId'] = \
            ipsec_site_connection['ikepolicy_id']
        ipsec_site_connectionInfo1['ipsecpolicyId'] = \
            ipsec_site_connection['ipsecpolicy_id']
        ipsec_site_connectionInfo1['vpnserviceId'] = \
            ipsec_site_connection['vpnservice_id']
        dpd = {}
        dpd['type'] = ipsec_site_connection['dpd']['action']
        dpd['interval'] = ipsec_site_connection['dpd']['interval']
        dpd['timeout'] = ipsec_site_connection['dpd']['timeout']
        ipsec_site_connectionInfo1['dpd'] = dpd
        ipsec_site_connectionInfo1['servicename'] = ''
        ipsec_site_connectionInfo0['ipsecsiteconn'] = \
            ipsec_site_connectionInfo1
        return ipsec_site_connectionInfo0

    def __restRequest__(self, id, entry_info, operation):
        LOG.debug(("the entry_info is %s"), entry_info)
        LOG.debug(("the id is %s"), id)
        service = RESTService()
        isNeedServiceName = False
        # entry_info['neutron_name'] = service.config["neutron_name"]

        if operation == OperationType.CREATE_IKEPOLICY:
            serviceName = 'create_ikepolicy'
            url = "/controller/dc/esdk/v2.0/ikepolicies"
            methodName = 'POST'
        elif operation == OperationType.DELETE_IKEPOLICY:
            serviceName = 'delete_ikepolicy'
            url = "/controller/dc/esdk/v2.0/ikepolicies"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_IKEPOLICY:
            serviceName = 'update_ikepolicy'
            url = "/controller/dc/esdk/v2.0/ikepolicies"
            methodName = 'PUT'
        elif operation == OperationType.CREATE_IPSECPOLICY:
            serviceName = 'create_ipsecpolicy'
            url = "/controller/dc/esdk/v2.0/ipsecpolicies"
            methodName = 'POST'
        elif operation == OperationType.DELETE_IPSECPOLICY:
            serviceName = 'delete_ipsecpolicy'
            url = "/controller/dc/esdk/v2.0/ipsecpolicies"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_IPSECPOLICY:
            serviceName = 'update_ipsecpolicy'
            url = "/controller/dc/esdk/v2.0/ipsecpolicies"
            methodName = 'PUT'
        elif operation == OperationType.CREATE_VPNSERVICE:
            serviceName = 'create_vpnservice'
            url = "/controller/dc/esdk/v2.0/vpnservice"
            methodName = 'POST'
        elif operation == OperationType.UPDATE_IKEPOLICY:
            serviceName = 'update_ikepolicy'
            url = "/controller/dc/esdk/v2.0/vpnservice"
            methodName = 'PUT'
        elif operation == OperationType.DELETE_VPNSERVICE:
            serviceName = 'delete_vpnservice'
            url = "/controller/dc/esdk/v2.0/vpnservice"
            methodName = 'DELETE'
        elif operation == OperationType.CREATE_IPSEC_SITE_CONNECTION:
            serviceName = 'create_ipsec_site_connection'
            url = "/controller/dc/esdk/v2.0/ipsecsiteconn"
            methodName = 'POST'
        elif operation == OperationType.DELETE_IPSEC_SITE_CONNECTION:
            serviceName = 'delete_ipsec_site_connection'
            url = "/controller/dc/esdk/v2.0/ipsecsiteconn"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_IPSEC_SITE_CONNECTION:
            serviceName = 'update_ipsec_site_connection'
            url = "/controller/dc/esdk/v2.0/ipsecsiteconn"
            methodName = 'PUT'
        else:
            LOG.debug(("the operation is wrong"))
        LOG.debug(("the serviceName is: %s"), serviceName)
        LOG.debug(("the ac_data is: %s"), json.dumps(entry_info))

        service.requestService(methodName,
                               url,
                               id,
                               entry_info,
                               isNeedServiceName,
                               self.__callBack__)

    def __callBack__(self, errorCode, reason, status, data=None):
        HuaweiIPsecVPNDriver.flag = True
        LOG.info("restRequest success")
        LOG.debug(("the reason is: %s"), reason)
        LOG.debug(("the errorCode is: %s"), errorCode)
        LOG.debug(("the status is: %s"), status)
        LOG.debug(("the data is: %s"), data)
        if status == 200 and reason is None:
            if errorCode != '0':
                LOG.debug(("raise IpSecError"))
                HuaweiIPsecVPNDriver.flag = True
                # raise ml2_exc.MechanismDriverError()
        elif status == 204:
            # HuaweiIPsecVPNDriver.flag = False
            pass
        else:
            LOG.debug(("raise IpSecError"))
            HuaweiIPsecVPNDriver.flag = False
            # raise ml2_exc.MechanismDriverError()


class OperationType(object):
    CREATE_IKEPOLICY = 1
    DELETE_IKEPOLICY = 2
    UPDATE_IKEPOLICY = 3
    CREATE_IPSECPOLICY = 4
    DELETE_IPSECPOLICY = 5
    UPDATE_IPSECPOLICY = 6
    CREATE_VPNSERVICE = 7
    UPDATE_VPNSERVICE = 8
    DELETE_VPNSERVICE = 9
    CREATE_IPSEC_SITE_CONNECTION = 10
    UPDATE_IPSEC_SITE_CONNECTION = 11
    DELETE_IPSEC_SITE_CONNECTION = 12
