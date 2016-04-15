import json
import re


from oslo_log import log as logging
from neutron.plugins.ml2 import driver_api as api
from neutron.plugins.ml2.common import exceptions as ml2_exc
# from neutron.plugins.openvswitch.common import constants
from neutron.restproxy.service.service import RESTService

from neutron.callbacks import events
from neutron.callbacks import registry
from neutron.callbacks import resources
# from neutron.extensions import securitygroup as ext_sg
# from neutron import manager
from neutron.extensions import portbindings
from neutron import context
from neutron.db import securitygroups_db as sg_db
from neutron.db import common_db_mixin


LOG = logging.getLogger(__name__)


global default_security_group_sync
global default_security_groups
default_security_group_sync = False
default_security_groups = []


def create_security_group(resource, event, trigger, **kwargs):
    LOG.info("[mech_huawei_driver] start create security group")
    security_group = kwargs['security_group']
    ctx = context.get_admin_context()
    try:
        securityGroupDb = SecurityGroupDbManager()
        sg_group = securityGroupDb\
            .get_security_group(ctx, security_group['id'])
        security_group['security_group_rules'] = \
            sg_group['security_group_rules']
    except Exception:
        LOG.warn("the sg group is not exsit")
    security_group_info = {}
    security_group_info = _set_security_group(security_group)
    LOG.info(
        "[mech_huawei_driver]security_group_info is %s",
        security_group_info)
    try:
        rest_request(
            security_group_info['id'],
            {'securityGroup': security_group_info},
            OperationType.CREATE_SECURITY_GROUP)
    except Exception:
        create_security_group_rollback(security_group_info['id'])
    LOG.info("[mech_huawei_driver]end creat security group")


def create_security_group_rollback(group_id):
    try:
        LOG.info("[mech_huawei_driver] start to \
            create security group rollback")
        rest_request(
            group_id,
            {},
            OperationType.DELETE_SECURITY_GROUP)
    except Exception:
        LOG.info("[mech_huawei_driver]rollback create security group fail.")


def update_security_group(resource, event, trigger, **kwargs):
    LOG.info("[mech_huawei_driver]start update security group")
    security_group = kwargs['security_group']
    security_group_info = {}
    security_group_info = _set_security_group(security_group)
    LOG.info("[mech_huawei_driver]the group is %s", security_group_info)
    try:
        rest_request(
                security_group_info['id'],
                {'securityGroup': security_group_info},
                OperationType.UPDATE_SECURITY_GROUP)
    except Exception:
        LOG.error("[mech_huawei_driver]update security group fail.")

    LOG.info("[mech_huawei_driver]end update security group")


def delete_security_group(resource, event, trigger, **kwargs):
    LOG.info("[mech_huawei_driver]start delete security group")
    group_id = kwargs['security_group_id']
    LOG.info("[mech_huawei_driver]the group id is %s", group_id)
    try:
        rest_request(
            group_id,
            {},
            OperationType.DELETE_SECURITY_GROUP)
    except Exception:
        LOG.error("[mech_huawei_driver]delete security group fail")

    LOG.info("[mech_huawei_driver]end delete security group")


def create_security_group_rule(resource, event, trigger, **kwargs):
    LOG.info("[mech_huawei_driver]start create security group rule")
    rule = kwargs['security_group_rule']
    rule_info = {}
    rule_info = _set_security_group_rule(rule)
    LOG.info("[mech_huawei_driver]the group rule is %s", rule_info)
    try:
        rest_request(
            rule_info['id'],
            {'securityGroupRule': rule_info},
            OperationType.CREATE_SECURITY_GROUP_RULE)
    except Exception:
        LOG.error("[mech_huawei_driver]create \
            security group rule fail,rollback")
        create_security_group_rule_rollback(rule_info['id'])

    LOG.info("[mech_huawei_driver]end create security group rule")


def create_security_group_rule_rollback(rule_id):
    try:
        LOG.info("[mech_huawei_driver]start to rollback rule.")
        rest_request(
            rule_id,
            {},
            OperationType.DELETE_SECURITY_GROUP_RULE)
    except Exception:
        LOG.error("[mech_huawei_driver]rollback group rule fail")


def update_security_group_rule(resource, event, trigger, **kwargs):
    pass


def delete_security_group_rule(resource, event, trigger, **kwargs):
    LOG.info("[mech_huawei_driver]start delete security group rule")
    rule_id = kwargs['security_group_rule_id']
    LOG.info("[mech_huawei_driver]the group rule is %s", rule_id)
    try:
        rest_request(
            rule_id,
            {},
            OperationType.DELETE_SECURITY_GROUP_RULE)
    except Exception:
        LOG.error("[mech_huawei_driver]delete security group rule fail")
    LOG.info("[mech_huawei_driver]end delete security group rule")


def delete_snat(resource, event, trigger, **kwargs):
    LOG.info("[mech_huawei_driver]start delete snat")
    LOG.info("[mech_huawei_driver]the kwargs is %s", kwargs)
    router_id = kwargs['router_id']
    LOG.info('-----AC:process_snat_delete--------')
    id = router_id
    try:
        rest_request(id, {}, OperationType.DELETE_SNAT)
    except Exception:
        LOG.info("[mech_huawei_driver]delete snat fail")
    LOG.info("[mech_huawei_driver]end delete snat")


def _set_security_group(security_group):
    security_group_info = {}
    security_group_info['tenantId'] = security_group['tenant_id']
    security_group_info['name'] = security_group['name']
    security_group_info['description'] = security_group['description']
    security_group_info['id'] = security_group['id']
    rule_arr = []
    for security_group_rule in security_group['security_group_rules']:
        rule_info = {}
        rule_info['tenantId'] = security_group_rule['tenant_id']
        rule_info['remoteGroupId'] = security_group_rule['remote_group_id']
        rule_info['direction'] = security_group_rule['direction']
        rule_info['remoteIpPrefix'] = security_group_rule['remote_ip_prefix']
        rule_info['protocol'] = security_group_rule['protocol']
        rule_info['portRangeMax'] = security_group_rule['port_range_max']
        rule_info['portRangeMin'] = security_group_rule['port_range_min']
        rule_info['id'] = security_group_rule['id']
        rule_info['etherType'] = security_group_rule['ethertype']
        rule_info['securityGroupId'] = security_group_rule['security_group_id']
        rule_arr.append(rule_info)

    security_group_info['securityGroupRuleList'] = rule_arr
    return security_group_info


def _set_security_group_rule(rule):
    rule_info = {}
    rule_info['remoteGroupId'] = rule['remote_group_id']
    rule_info['direction'] = rule['direction']
    rule_info['remoteIpPrefix'] = rule['remote_ip_prefix']
    rule_info['protocol'] = rule['protocol']
    rule_info['etherType'] = rule['ethertype']
    rule_info['tenantId'] = rule['tenant_id']
    rule_info['portRangeMax'] = rule['port_range_max']
    rule_info['portRangeMin'] = rule['port_range_min']
    rule_info['id'] = rule['id']
    rule_info['securityGroupId'] = rule['security_group_id']
    return rule_info


def rest_request(id, entry_info, operation):
    LOG.info("[mech_huawei_driver]begin to restful request")
    LOG.debug(("[mech_huawei_driver]the entry_info is %s"), entry_info)
    LOG.debug(("[mech_huawei_driver]the id is %s"), id)
    service = RESTService()
    isNeedServiceName = False
    if operation == OperationType.CREATE_SECURITY_GROUP:
        url = "/controller/dc/esdk/v2.0/neutronapi/security-groups"
        methodName = 'POST'
    elif operation == OperationType.UPDATE_SECURITY_GROUP:
        url = "/controller/dc/esdk/v2.0/neutronapi/security-groups"
        methodName = 'PUT'
    elif operation == OperationType.DELETE_SECURITY_GROUP:
        url = "/controller/dc/esdk/v2.0/neutronapi/security-groups"
        methodName = 'DELETE'
    elif operation == OperationType.CREATE_SECURITY_GROUP_RULE:
        url = "/controller/dc/esdk/v2.0/neutronapi/security-group-rules"
        methodName = 'POST'
    elif operation == OperationType.DELETE_SECURITY_GROUP_RULE:
        url = "/controller/dc/esdk/v2.0/neutronapi/security-group-rules"
        methodName = 'DELETE'
    elif operation == OperationType.DELETE_SNAT:
        url = "/controller/dc/esdk/v2.0/snats"
        methodName = 'DELETE'
    else:
        LOG.debug(("[mech_huawei_driver]the operation is wrong"))

    LOG.debug(
        ("[mech_huawei_driver]the ac_data is: %s"),
        json.dumps(entry_info))
    try:
        if operation == OperationType\
            .CREATE_SECURITY_GROUP\
                and entry_info['securityGroup']['name'] == 'default':
            default_security_group_sync = False
            service.requestService(methodName,
                                   url,
                                   id,
                                   entry_info,
                                   isNeedServiceName,
                                   default_security_group_rest_callback)
            if default_security_group_sync:
                default_security_groups\
                    .append(entry_info['securityGroup']['id'])
        else:
            if operation == OperationType.DELETE_SECURITY_GROUP:
                for group_id in default_security_groups:
                    if group_id == entry_info['securityGroup']['id']:
                        default_security_groups\
                            .remove(entry_info['securityGroup']['id'])
            service.requestService(methodName,
                                   url,
                                   id,
                                   entry_info,
                                   isNeedServiceName,
                                   rest_callback)
    except Exception as e:
        LOG.debug("[mech_huawei_driver]exception is %s", e)


def rest_callback(errorCode, reason, status, data=None):
    LOG.info("[mech_huawei_driver]rest request success")
    LOG.debug(("[mech_huawei_driver]the reason is: %s"), reason)
    LOG.debug(("[mech_huawei_driver]the errorCode is: %s"), errorCode)
    LOG.debug(("[mech_huawei_driver]the status is: %s"), status)
    LOG.debug(("[mech_huawei_driver]the data is: %s"), data)
    if status == 200 and reason is None:
        if errorCode != '0':
            LOG.debug(("[mech_huawei_driver]raise MechanismDriverError"))
            raise ml2_exc.MechanismDriverError()
    elif status == 204:
        pass
    else:
        LOG.debug(("[mech_huawei_driver]raise MechanismDriverError"))


def default_security_group_rest_callback(
                                errorCode, reason, status, data=None):
    LOG.info("[mech_huawei_driver]default_security_group request success")
    LOG.debug(("[mech_huawei_driver]the reason is: %s"), reason)
    LOG.debug(("[mech_huawei_driver]the errorCode is: %s"), errorCode)
    LOG.debug(("[mech_huawei_driver]the status is: %s"), status)
    LOG.debug(("[mech_huawei_driver]the data is: %s"), data)
    if status == 200 and reason is None:
        if errorCode != '0':
            LOG.debug(("[mech_huawei_driver]raise MechanismDriverError"))
            raise ml2_exc.MechanismDriverError()
    elif status == 204:
        pass
    else:
        LOG.debug(("[mech_huawei_driver]default_security_group request Error"))


class SecurityGroupDbManager(
            sg_db.SecurityGroupDbMixin, common_db_mixin.CommonDbMixin):
    pass


class HuaweiACMechanismDriver(api.MechanismDriver):

    def initialize(self):
        LOG.info("[mech_huawei_driver]init huawei driver")
        self.ctx = context.get_admin_context()
        self.securityGroupDb = SecurityGroupDbManager()
        registry.subscribe(
            delete_snat, resources.ROUTER_GATEWAY, events.BEFORE_DELETE)
        registry.subscribe(
            create_security_group, resources.SECURITY_GROUP,
            events.AFTER_CREATE)
        registry.subscribe(
            update_security_group, resources.SECURITY_GROUP,
            events.AFTER_UPDATE)
        registry.subscribe(
            delete_security_group, resources.SECURITY_GROUP,
            events.AFTER_DELETE)
        registry.subscribe(
            create_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.AFTER_CREATE)
        registry.subscribe(
            update_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.AFTER_UPDATE)
        registry.subscribe(
            delete_security_group_rule, resources.SECURITY_GROUP_RULE,
            events.AFTER_DELETE)

    def create_network_postcommit(self, context):
        LOG.debug(("----------the sence is create network."))
        network_info = self.__setNetWorkInfo__(context)
        operation = OperationType.CREATE_NETWORK
        LOG.info("----------network_info is:%s", network_info)
        self.__restRequest__("", network_info, operation)

    def delete_network_postcommit(self, context):
        LOG.debug(("----------the sence is delete network."))
        network_info = self.__setNetWorkInfo__(context)
        operation = OperationType.DELETE_NETWORK
        self.__restRequest__(network_info['network']['id'], {}, operation)

    def update_network_postcommit(self, context):
        LOG.debug(("----------the sence is update network."))
        network_info = self.__setNetWorkInfo__(context)
        operation = OperationType.UPDATE_NETWORK
        LOG.info("----------network_info is:%s", network_info)
        self.__restRequest__(
            network_info['network']['id'], network_info, operation)

    def __setNetWorkInfo__(self, context):
        LOG.debug(
            ("----------the context current in network is %s"),
            context.current)
        network_info = {}
        network_info['id'] = context.current['id']
        network_info['status'] = context.current['status']
        network_info['segmentationId']\
            = context.current['provider:segmentation_id']
        network_info['tenantId'] = context.current['tenant_id']
        network_info['name'] = context.current['name']
        network_info['adminStateUp'] = context.current['admin_state_up']
        network_info['shared'] = context.current['shared']
        network_info['networkType'] = context.current['provider:network_type']
        network_info['physicalNetwork']\
            = context.current['provider:physical_network']
        if 'router:external' in context.current\
                and context.current['router:external']:
            network_info['routerExternal'] = True
            LOG.debug(("----------it is a external network."))
        else:
            network_info['routerExternal'] = False
            LOG.debug(("----------it is a internal network."))
        LOG.debug(("the network_info is %s"), network_info)
        network_info1 = {}
        network_info1['network'] = network_info
        return network_info1

    def create_subnet_postcommit(self, context):
        LOG.debug(("----------the sence is create subnet."))
        operation = OperationType.CREATE_SUBNET
        subnet_info = self.__setSubNetinfo__(context, operation)
        self.__restRequest__("", subnet_info, operation)

    def delete_subnet_postcommit(self, context):
        LOG.debug(("----------the sence is delete subnet."))
        operation = OperationType.DELETE_SUBNET
        subnet_info = self.__setSubNetinfo__(context, operation)
        self.__restRequest__(subnet_info['subnet']['id'], {}, operation)

    def update_subnet_postcommit(self, context):
        LOG.debug(("----------the sence is update subnet."))
        operation = OperationType.UPDATE_SUBNET
        subnet_info = self.__setSubNetinfo__(context, operation)
        self.__restRequest__(
            subnet_info['subnet']['id'], subnet_info, operation)

    def __setSubNetinfo__(self, context, operation):
        LOG.debug(
            ("----------the context current in subnet is %s"),
            context.current)
        subnet_info = {}
        subnet_info1 = {}
        subnet_info['networkId'] = context.current['network_id']
        subnet_info['tenantId'] = context.current['tenant_id']
        subnet_info['id'] = context.current['id']
        subnet_info['name'] = context.current['name']
        subnet_info['ipVersion'] = context.current['ip_version']
        subnet_info['enableDhcp'] = context.current['enable_dhcp']
        subnet_info['allocationPools'] = context.current['allocation_pools']
        subnet_info['cidr'] = context.current['cidr']
        subnet_info['gatewayIp'] = context.current['gateway_ip']
        subnet_info['dnsNameservers'] = context.current['dns_nameservers']
        subnet_info['hostRoutes'] = context.current['host_routes']
        if 6 == context.current['ip_version']:
            subnet_info['ipv6AddressMode']\
                = context.current['ipv6_address_mode']
            subnet_info['ipv6RaMode'] = context.current['ipv6_ra_mode']

        LOG.debug(("the subnet_info is %s"), subnet_info)
        subnet_info1['subnet'] = subnet_info
        return subnet_info1

    def create_port_postcommit(self, context):
        LOG.debug(("----------create_port_postcommit is in."))
        LOG.debug(
            ("----------the device_owner is %s."),
            context.current['device_owner'])
        LOG.debug(("----------the sence is create port."))
        self.__deal_port__(context, OperationType.CREATE_PORT)

    def update_port_postcommit(self, context):
        LOG.debug(("----------update_port_postcommit is in."))
        LOG.debug(
            ("----------the device_owner is %s."),
            context.current['device_owner'])
        LOG.debug(
            ("----------the port status is %s."),
            context.current['status'])
        self.__deal_port__(context, OperationType.UPDATE_PORT)

    def delete_port_precommit(self, context):
        LOG.debug(("----------delete_port_postcommit is in."))
        LOG.debug(
            ("----------the device_owner is %s."),
            context.current['device_owner'])
        operation = OperationType.DELETE_PORT
        port_info = self.__setPortinfo__(context, operation)
        self.__restRequest__(port_info['port']['id'], port_info, operation)

    def __deal_port__(self, context, operation):
        port_info = self.__setPortinfo__(context, operation)
        # if the port bind default security group and not sync to ac,
        # it need to be sync to ac
        if operation == OperationType.CREATE_PORT:
            for security_group_id in context.current['security_groups']:
                sg_group = self\
                    .securityGroupDb.get_security_group(
                        self.ctx, security_group_id)
                security_group_info = _set_security_group(sg_group)
                if security_group_info['name'] == 'default' and not self\
                        .__check_default_security_group(security_group_id):
                    LOG.info(
                        "[mech_huawei_driver]security_group_info is %s",
                        security_group_info)
                    rest_request(security_group_info['id'],
                                 {'securityGroup': security_group_info},
                                 OperationType.CREATE_SECURITY_GROUP)

        self.__restRequest__(port_info['port']['id'], port_info, operation)

    def __check_default_security_group(self, security_group_id):
        for sg_id in default_security_groups:
            if sg_id == security_group_id:
                return True
        return False

    def bind_port(self, context):
        LOG.debug("Attempting to bind port %(port)s on network %(network)s",
                  {'port': context.current['id'],
                   'network': context.network.current['id']})
        for segment in context.segments_to_bind:
            context._new_bound_segment = segment[api.ID]
            vif_details = {portbindings.OVS_HYBRID_PLUG: True}
            context.set_binding(segment[api.ID],
                                'ovs',
                                vif_details)

    def __is_device_owner_compute__(self, context):
        device_owner = context.current['device_owner']
        if device_owner.find("compute") == 0:
            return True
        else:
            return False

    def __setPortinfo__(self, context, operation):
        LOG.debug(
            ("----------the context current in Port is %s"),
            context.current)
        port_info = {}
        port_info1 = {}
        port_info['id'] = context.current['id']
        port_info['name'] = context.current['name']
        port_info['networkId'] = context.current['network_id']
        port_info['tenantId'] = context.current['tenant_id']
        port_info['hostId'] = context.current['binding:host_id']
        port_info['macAddress'] = context.current['mac_address']
        # self.__setMacFormat__(context.current['mac_address'])
        port_info['adminStateUp'] = context.current['admin_state_up']
        port_info['deviceOwner'] = context.current['device_owner']
        # port_info["profile"] = ''
        port_info['profile'] = {}
        port_info['profile']['localLinkInformations'] = []
        if context.current in ('binding:profile') \
            and context.current['binding:profile'] \
                in ('local_link_information'):
            for link in context\
                    .current['binding:profile']['local_link_information']:
                link_ac = {}
                link_ac['switchId'] = link['swich_id']
                link_ac['mgmtIp'] = link['mgmtIP']
                link_ac['bondType'] = link['bondtype']
                link_ac['portId'] = link['port_id']
                link_ac['switchInfo'] = link['switch_info']
                port_info['profile']['localLinkInformations'].append(link_ac)
                port_info['vifType'] = context.current['binding:vif_type']
                port_info['vnicType'] = context.current['binding:vnic_type']
                port_info['deviceId'] = context.current['device_id']
                port_info['status'] = context.current['status']
        if context.current['fixed_ips']:
            fixedIps = {}
            fixedIp = []
            for ietm in context.current['fixed_ips']:
                fixedIps['subnetId'] = ietm['subnet_id']
                fixedIps['ipAddress'] = ietm['ip_address']
                fixedIp.append(fixedIps)
            port_info['fixedIps'] = fixedIp
        port_info['sercurityGroups'] = context.current['security_groups']
        LOG.debug(("the port_info is %s"), port_info)
        port_info1['port'] = port_info
        return port_info1

    def __restRequest__(self, id, entry_info, operation):

        LOG.debug(("the entry_info is %s"), entry_info)
        LOG.debug(("the id is %s"), id)
        service = RESTService()
        isNeedServiceName = False

        if operation == OperationType.CREATE_NETWORK:
            serviceName = 'create_network'
            url = "/controller/dc/esdk/v2.0/networks"
            methodName = 'POST'
            isNeedServiceName = True
        elif operation == OperationType.DELETE_NETWORK:
            serviceName = 'delete_network'
            url = "/controller/dc/esdk/v2.0/networks"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_NETWORK:
            serviceName = 'update_network'
            url = "/controller/dc/esdk/v2.0/networks"
            methodName = 'PUT'
        elif operation == OperationType.CREATE_SUBNET:
            serviceName = 'create_subnet'
            url = "/controller/dc/esdk/v2.0/subnets"
            methodName = 'POST'
            isNeedServiceName = True
        elif operation == OperationType.DELETE_SUBNET:
            serviceName = 'delete_subnet'
            url = "/controller/dc/esdk/v2.0/subnets"
            methodName = 'DELETE'
        elif operation == OperationType.CREATE_PORT:
            serviceName = 'create_port'
            url = "/controller/dc/esdk/v2.0/ports"
            methodName = 'POST'
            isNeedServiceName = True
        elif operation == OperationType.UPDATE_PORT:
            serviceName = 'update_port'
            url = "/controller/dc/esdk/v2.0/ports"
            methodName = 'PUT'
        elif operation == OperationType.DELETE_PORT:
            serviceName = 'delete_port'
            url = "/controller/dc/esdk/v2.0/ports"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_SUBNET:
            serviceName = 'update_subnet'
            url = "/controller/dc/esdk/v2.0/subnets"
            methodName = 'PUT'
        elif operation == OperationType.DELETE_SNAT:
            serviceName = 'delete_snat'
            url = "/controller/dc/esdk/v2.0/snats"
            methodName = 'DELETE'
        else:
            LOG.debug(("----------the operation is wrong"))

        LOG.debug(("----------the serviceName is: %s"), serviceName)
        LOG.debug(("---------- the ac_data is: %s"), json.dumps(entry_info))

        service.requestService(methodName,
                               url,
                               id,
                               entry_info,
                               isNeedServiceName,
                               self.__callBack__)

    def __callBack__(self, errorCode, reason, status, data=None):
        LOG.info("----------restRequest success")
        LOG.debug(("----------the reason is: %s"), reason)
        LOG.debug(("----------the errorCode is: %s"), errorCode)
        LOG.debug(("----------the status is: %s"), status)
        LOG.debug(("----------the data is: %s"), data)
        if status == 200 and reason is None:
            if errorCode != '0':
                LOG.debug(("----------raise MechanismDriverError"))
                raise ml2_exc.MechanismDriverError()
        elif status == 204:
            pass
        else:
            LOG.debug(("----------raise MechanismDriverError"))
            raise ml2_exc.MechanismDriverError()

    def __setMacFormat__(self, mac_address):
        pureMac = re.sub("[^a-zA-Z0-9]", "", mac_address)
        tmpMac = re.findall(r'.{4}', pureMac)
        macReturn = '-'.join(tmpMac)
        return macReturn

    def __restRequestError__(self, errorCode, reason):
        LOG.error("----------restRequest error")
        LOG.debug(("----------the reason is: %s"), reason)
        LOG.debug(("----------the errorCode is: %s"), errorCode)
        raise ml2_exc.MechanismDriverError()


class OperationType(object):
    CREATE_NETWORK = 1
    DELETE_NETWORK = 2
    CREATE_SUBNET = 3
    DELETE_SUBNET = 4
    CREATE_PORT = 5
    UPDATE_PORT = 6
    DELETE_PORT = 7
    UPDATE_SUBNET = 8
    UPDATE_NETWORK = 9
    CREATE_SECURITY_GROUP = 10
    UPDATE_SECURITY_GROUP = 11
    DELETE_SECURITY_GROUP = 12
    CREATE_SECURITY_GROUP_RULE = 13
    DELETE_SECURITY_GROUP_RULE = 14
DELETE_SNAT = 15
