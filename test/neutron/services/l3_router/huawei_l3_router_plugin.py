# Copyright (c) 2013 OpenStack Foundation.
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

from oslo_config import cfg
from oslo_utils import importutils
from oslo_log import log as logging
import json
from neutron.db import l3_db
from neutron.db import l3_dvrscheduler_db
from neutron.plugins.common import constants
from neutron.services.l3_router import l3_router_plugin
from neutron.restproxy.service.service import RESTService

LOG = logging.getLogger(__name__)


class HuaweiL3RouterPlugin(l3_router_plugin.L3RouterPlugin):

    """Implementation of the Neutron L3 Router Service Plugin.

    This class implements a L3 service plugin that provides
    router and floatingip resources and manages associated
    request/response.
    All DB related work is implemented in classes
    l3_db.L3_NAT_db_mixin, l3_hamode_db.L3_HA_NAT_db_mixin,
    l3_dvr_db.L3_NAT_with_dvr_db_mixin, and extraroute_db.ExtraRoute_db_mixin.
    """

    def __init__(self):
        super(HuaweiL3RouterPlugin, self).setup_rpc()
        self.router_scheduler = importutils.import_object(
            cfg.CONF.router_scheduler_driver)
        self.start_periodic_l3_agent_status_check()
        super(HuaweiL3RouterPlugin, self).__init__()
        if 'dvr' in self.supported_extension_aliases:
            l3_dvrscheduler_db.subscribe()
        l3_db.subscribe()

    def get_plugin_type(self):
        return constants.L3_ROUTER_NAT

    def get_plugin_description(self):
        """returns string description of the plugin."""
        return ("Huawei L3 Router Service Plugin for basic L3 forwarding"
                " between (L2) Neutron networks and access to external"
                " networks via a NAT gateway.")

    def create_router(self, context, router):
        LOG.debug(('__________1____________create_router %s'), router)
        router_db = super(HuaweiL3RouterPlugin, self)\
            .create_router(context, router)
        LOG.debug(('__________2____________create_router %s'), router_db)

        routerinfo = {}
        routerinfo['id'] = router_db['id']
        routerinfo['name'] = router_db['name']
        routerinfo['adminStateUp'] = router_db['admin_state_up']
        routerinfo['tenantId'] = router_db['tenant_id']
        routerinfo['externalGatewayInfo'] = router_db['external_gateway_info']
        routerinfo['distributed'] = router_db['distributed']
        routerinfo['ha'] = router_db['ha']
        routerinfo['routes'] = router_db['routes']

        operation = OperationType.CREATE_ROUTER
        info = {}
        info['router'] = routerinfo
        self.__restRequest__("", info, operation)
        return router_db

    def add_router_interface(self, context, router_id, interface_info):
        LOG.debug(
            ('__________1____________add_router_interface %s'), interface_info)
        interface_info = super(HuaweiL3RouterPlugin, self)\
            .add_router_interface(context, router_id, interface_info)
        router = super(HuaweiL3RouterPlugin, self)\
            .get_router(context, router_id)
        LOG.debug(
            ('__________2____________add_router_interface %s'), interface_info)
        LOG.debug(('__________3____________add_router_interface %s'), router)

        operation = OperationType.ADD_ROUTER_INTERFACE
        service = RESTService()

        service_Name = service.config["service_name"]
        rest_info = {}
        info = {}
        info['portId'] = interface_info['port_id']
        info['routerId'] = router_id
        info['serviceName'] = service_Name
        info['tenantId'] = router['tenant_id']

        rest_info['routerInterface'] = info

        self.__restRequest__(router_id, rest_info, operation)

    def remove_router_interface(self, context, router_id, interface_info):
        LOG.debug(
            ('__________1____________remove_router_interface %s'),
            interface_info)
        router = super(HuaweiL3RouterPlugin, self)\
            .get_router(context, router_id)
        operation = OperationType.DELETE_ROUTER_INTERFACE
        service = RESTService()
        service_Name = service.config["service_name"]

        rest_info = {}
        rest_info['portId'] = interface_info['port_id']
        rest_info['id'] = router_id
        rest_info['serviceName'] = service_Name
        rest_info['tenantId'] = router['tenant_id']

        self.__restRequest__(router_id, rest_info, operation)
        super(HuaweiL3RouterPlugin, self)\
            .remove_router_interface(context, router_id, interface_info)

    def delete_router(self, context, id):
        operation = OperationType.DELETE_ROUTER
        info = {}
        self.__restRequest__(id, info, operation)
        super(HuaweiL3RouterPlugin, self).delete_router(context, id)

    def __restRequest__(self, id, entry_info, operation):
        pass

        LOG.debug(("the entrxy_info is %s"), entry_info)
        LOG.debug(("the id is %s"), id)
        service = RESTService()
        isNeedServiceName = False

        if operation == OperationType.ADD_ROUTER_INTERFACE:
            serviceName = 'add_router_interface'
            url = "/controller/dc/esdk/v2.0/\
                routerinterface/add_router_interface"
            LOG.info(("the request address %s"), url)
            methodName = 'PUT'
        elif operation == OperationType.DELETE_ROUTER_INTERFACE:
            serviceName = 'delete_router_interface'
            url = "/controller/dc/esdk/v2.0/\
                routerinterface/remove_router_interface"
            methodName = 'PUT'
        elif operation == OperationType.DELETE_ROUTER:
            serviceName = 'delete_router'
            url = "/controller/dc/esdk/v2.0/routers"
            methodName = 'DELETE'
        elif operation == OperationType.CREATE_ROUTER:
            serviceName = 'create_router'
            url = "/controller/dc/esdk/v2.0/routers"
            methodName = 'POST'
        else:
            LOG.debug(("----------the operation is wrong"))

        LOG.debug(("----------the serviceName is: %s"), serviceName)
        LOG.debug(("---------- the ac_data is: %s"), json.dumps(entry_info))

        service.requestService(
                           methodName,
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
                raise Exception
        elif status == 204:
            pass
        else:
            LOG.debug(("----------raise MechanismDriverError"))
            raise Exception


class OperationType(object):
    ADD_ROUTER_INTERFACE = 1
    DELETE_ROUTER_INTERFACE = 2
    DELETE_ROUTER = 3
    CREATE_ROUTER = 4
