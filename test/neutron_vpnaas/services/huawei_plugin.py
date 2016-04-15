#    (c) Copyright 2013 Hewlett-Packard Development Company, L.P.
#    All Rights Reserved.
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

from neutron.i18n import _LI
from neutron.plugins.common import constants
from neutron.services import service_base
from oslo_log import log as logging

from neutron_vpnaas.services.vpn.plugin import VPNDriverPlugin

LOG = logging.getLogger(__name__)


class HuaweiVPNDriverPlugin(VPNDriverPlugin):
    """VpnPlugin which supports VPN Service Drivers."""
    # TODO(nati) handle ikepolicy and ipsecpolicy update usecase
    def __init__(self):
        super(HuaweiVPNDriverPlugin, self).__init__()
        # Load the service driver from neutron.conf.
        drivers, default_provider = service_base.load_drivers(
            constants.VPN, self)
        LOG.info(_LI("VPN plugin using service driver: %s"), default_provider)
        self.ipsec_driver = drivers[default_provider]

    def _get_driver_for_vpnservice(self, vpnservice):
        return self.ipsec_driver

    def _get_driver_for_ipsec_site_connection(self, context,
                                              ipsec_site_connection):
        # TODO(nati) get vpnservice when we support service type framework
        vpnservice = None
        return self._get_driver_for_vpnservice(vpnservice)

    def _get_driver_for_ikepolicy(self, context, ikepolicy):

        vpnservice = None
        return self._get_driver_for_vpnservice(vpnservice)

    def _get_driver_for_ipsecpolicy(self, context, ipsecpolicy):
        vpnservice = None
        return self._get_driver_for_vpnservice(vpnservice)

    def _get_validator(self):
        return self.ipsec_driver.validator

    def create_ikepolicy(self, context, ikepolicy):
        ikepolicy = super(
            HuaweiVPNDriverPlugin, self).create_ikepolicy(
                context, ikepolicy)
        driver = self._get_driver_for_ikepolicy(
            context, ikepolicy)
        driver.create_ikepolicy(context, ikepolicy)

        if(driver.flag is False):
            super(HuaweiVPNDriverPlugin, self).delete_ikepolicy(
                context, ikepolicy['id'])
            raise Exception
        return ikepolicy

    def delete_ikepolicy(self, context, ikepolicy_id):
        ikepolicy = super(
            HuaweiVPNDriverPlugin, self).get_ikepolicy(
                context, ikepolicy_id)
        driver = self._get_driver_for_ikepolicy(
            context, ikepolicy)
        driver.delete_ikepolicy(context, ikepolicy)
        if(driver.flag is False):
            raise Exception
        super(HuaweiVPNDriverPlugin, self).delete_ikepolicy(context,
                                                            ikepolicy_id)

    def update_ikepolicy(self, context, ikepolicy_id, ikepolicy):
        old_ikepolicy = self.get_ikepolicy(context, ikepolicy_id)
        LOG.debug(("update_ikepolicy the ikepolicy is %s."),
                  ikepolicy)
        ikepolicy = super(
            HuaweiVPNDriverPlugin, self).update_ikepolicy(
                context,
                ikepolicy_id,
                ikepolicy)
        LOG.debug(("update_ikepolicy the ikepolicy is %s."),
                  ikepolicy)
        driver = self._get_driver_for_ikepolicy(
            context, ikepolicy)
        driver.update_ikepolicy(context, old_ikepolicy, ikepolicy)
        return ikepolicy

    def create_ipsecpolicy(self, context, ipsecpolicy):
        ipsecpolicy = super(
            HuaweiVPNDriverPlugin, self).create_ipsecpolicy(context,
                                                            ipsecpolicy)
        driver = self._get_driver_for_ipsecpolicy(
            context, ipsecpolicy)
        driver.create_ipsecpolicy(context, ipsecpolicy)

        if(driver.flag is False):
            super(HuaweiVPNDriverPlugin, self).\
                delete_ipsecpolicy(context, ipsecpolicy['id'])
            raise Exception
        return ipsecpolicy

    def delete_ipsecpolicy(self, context, ipsecpolicy_id):
        ipsecpolicy = super(
            HuaweiVPNDriverPlugin, self).get_ipsecpolicy(
                context, ipsecpolicy_id)
        driver = self._get_driver_for_ipsecpolicy(
            context, ipsecpolicy)
        driver.delete_ipsecpolicy(context, ipsecpolicy)
        if(driver.flag is False):
            raise Exception
        super(HuaweiVPNDriverPlugin, self).delete_ipsecpolicy(context,
                                                              ipsecpolicy_id)

    def update_ipsecpolicy(self, context, ipsecpolicy_id, ipsecpolicy):
        old_ipsecpolicy = self.get_ipsecpolicy(context,
                                               ipsecpolicy_id)
        ipsecpolicy = super(
            HuaweiVPNDriverPlugin, self).update_ipsecpolicy(
                context,
                ipsecpolicy_id,
                ipsecpolicy)
        driver = self._get_driver_for_ipsecpolicy(
            context, ipsecpolicy)
        driver.update_ipsecpolicy(context, old_ipsecpolicy, ipsecpolicy)
        return ipsecpolicy

    def create_vpnservice(self, context, vpnservice):
        vpnservice = super(
            HuaweiVPNDriverPlugin, self).create_vpnservice(
                context, vpnservice)
        driver = self._get_driver_for_vpnservice(vpnservice)
        driver.create_vpnservice(context, vpnservice)

        if(driver.flag is False):
            super(HuaweiVPNDriverPlugin, self).\
                delete_vpnservice(context, vpnservice['id'])
            raise Exception
        return vpnservice

    def delete_vpnservice(self, context, vpnservice_id):
        vpnservice = self._get_vpnservice(context, vpnservice_id)
        driver = self._get_driver_for_vpnservice(vpnservice)
        driver.delete_vpnservice(context, vpnservice)
        if(driver.flag is False):
            raise Exception
        super(VPNDriverPlugin, self).delete_vpnservice(context, vpnservice_id)

    def create_ipsec_site_connection(self, context, ipsec_site_connection):
        LOG.info("create_ipsec_site_connection")
        ipsec_site_connection = super(
            HuaweiVPNDriverPlugin, self).create_ipsec_site_connection(
                context, ipsec_site_connection)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        # driver.create_ipsec_site_connection(context, ipsec_site_connection)

        if(driver.flag is False):
            super(HuaweiVPNDriverPlugin, self).\
                delete_ipsec_site_connection(context,
                                             ipsec_site_connection['id'])
            raise Exception
        return ipsec_site_connection

    def delete_ipsec_site_connection(self, context, ipsec_conn_id):
        ipsec_site_connection = self.get_ipsec_site_connection(
            context, ipsec_conn_id)
        driver = self._get_driver_for_ipsec_site_connection(
            context, ipsec_site_connection)
        driver.delete_ipsec_site_connection(context, ipsec_site_connection)
        if(driver.flag is False):
            raise Exception
        super(VPNDriverPlugin, self).delete_ipsec_site_connection(
            context, ipsec_conn_id)
