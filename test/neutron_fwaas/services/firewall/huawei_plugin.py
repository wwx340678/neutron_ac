'''
Created on 2015-11-2

@author: sWX283609
'''
from neutron.api.v2 import attributes as attr
from neutron.common import rpc as n_rpc
from neutron.common import topics
from neutron import context as neutron_context
from neutron.i18n import _LW
from neutron import manager
from neutron.plugins.common import constants as const
from oslo_config import cfg
from oslo_log import log as logging
from neutron.restproxy.service.service import RESTService
import oslo_messaging
import json
from neutron_fwaas.db.firewall import firewall_db
from neutron_fwaas.db.firewall import firewall_router_insertion_db
from neutron_fwaas.extensions import firewall as fw_ext


LOG = logging.getLogger(__name__)


class FirewallCallbacks(object):

    target = oslo_messaging.Target(version='1.0')

    def __init__(self, plugin):
        super(FirewallCallbacks, self).__init__()
        self.plugin = plugin

    def set_firewall_status(self, context, firewall_id, status, **kwargs):
        """Agent uses this to set a firewall's status."""
        LOG.debug("set_firewall_status() called")
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # ignore changing status if firewall expects to be deleted
            # That case means that while some pending operation has been
            # performed on the backend, neutron server received delete request
            # and changed firewall status to const.PENDING_DELETE
            if fw_db.status == const.PENDING_DELETE:
                LOG.debug("Firewall %(fw_id)s in PENDING_DELETE state, "
                          "not changing to %(status)s",
                          {'fw_id': firewall_id, 'status': status})
                return False
            if status in (const.ACTIVE, const.DOWN, const.INACTIVE):
                fw_db.status = status
                return True
            else:
                fw_db.status = const.ERROR
                return False

    def firewall_deleted(self, context, firewall_id, **kwargs):
        """Agent uses this to indicate firewall is deleted."""
        LOG.debug("firewall_deleted() called")
        with context.session.begin(subtransactions=True):
            fw_db = self.plugin._get_firewall(context, firewall_id)
            # allow to delete firewalls in ERROR state
            if fw_db.status in (const.PENDING_DELETE, const.ERROR):
                self.plugin.delete_db_firewall_object(context, firewall_id)
                return True
            else:
                LOG.warn(_LW('Firewall %(fw)s unexpectedly deleted by agent, '
                             'status was %(status)s'),
                         {'fw': firewall_id, 'status': fw_db.status})
                fw_db.status = const.ERROR
                return False

    def get_firewalls_for_tenant(self, context, **kwargs):
        """Agent uses this to get all firewalls and rules for a tenant."""
        LOG.debug("get_firewalls_for_tenant() called")
        fw_list = []
        for fw in self.plugin.get_firewalls(context):
            fw_with_rules = self.plugin._make_firewall_dict_with_rules(
                context, fw['id'])
            if fw['status'] == const.PENDING_DELETE:
                fw_with_rules['add-router-ids'] = []
                fw_with_rules['del-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
            else:
                fw_with_rules['add-router-ids'] = (
                    self.plugin.get_firewall_routers(context, fw['id']))
                fw_with_rules['del-router-ids'] = []
            fw_list.append(fw_with_rules)
        return fw_list

    def get_firewalls_for_tenant_without_rules(self, context, **kwargs):
        """Agent uses this to get all firewalls for a tenant."""
        LOG.debug("get_firewalls_for_tenant_without_rules() called")
        fw_list = [fw for fw in self.plugin.get_firewalls(context)]
        return fw_list

    def get_tenants_with_firewalls(self, context, **kwargs):
        """Agent uses this to get all tenants that have firewalls."""
        LOG.debug("get_tenants_with_firewalls() called")
        ctx = neutron_context.get_admin_context()
        fw_list = self.plugin.get_firewalls(ctx)
        fw_tenant_list = list(set(fw['tenant_id'] for fw in fw_list))
        return fw_tenant_list


class FirewallAgentApi(object):
    """Plugin side of plugin to agent RPC API."""
    def __init__(self, topic, host):
        self.host = host
        target = oslo_messaging.Target(topic=topic, version='1.0')
        self.client = n_rpc.get_client(target)

    def create_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'create_firewall', firewall=firewall,
                   host=self.host)

    def update_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'update_firewall', firewall=firewall,
                   host=self.host)

    def delete_firewall(self, context, firewall):
        cctxt = self.client.prepare(fanout=True)
        cctxt.cast(context, 'delete_firewall', firewall=firewall,
                   host=self.host)


class OperationType(object):
    CREATE_FIREWALL_RULE = 1
    DELETE_FIREWALL_RULE = 2
    UPDATE_FIREWALL_RULE = 3
    CREATE_FIREWALL_POLICY = 4
    DELETE_FIREWALL_POLICY = 5
    UPDATE_FIREWALL_POLICY = 6
    CREATE_FIREWALL = 7
    UPDATE_FIREWALL = 8
    DELETE_FIREWALL = 9
    INSERT_FIREWALL_RULE = 11
    REMOVE_FIREWALL_RULE = 12


class HuaweiFWAASDriverPlugin(firewall_db.Firewall_db_mixin,
                              firewall_router_insertion_db.
                              FirewallRouterInsertionDbMixin):
    """Implementation of the Neutron Firewall Service Plugin.

    This class manages the workflow of FWaaS request/response.
    Most DB related works are implemented in class
    firewall_db.Firewall_db_mixin.
    """
    supported_extension_aliases = ["fwaas", "fwaasrouterinsertion"]

    def __init__(self):
        """Do the initialization for the firewall service plugin here."""
        self.endpoints = [FirewallCallbacks(self)]

        self.conn = n_rpc.create_connection(new=True)
        self.conn.create_consumer(
            topics.FIREWALL_PLUGIN, self.endpoints, fanout=False)
        self.conn.consume_in_threads()

        self.agent_rpc = FirewallAgentApi(
            topics.L3_AGENT,
            cfg.CONF.host
        )
        firewall_db.subscribe()

    def _rpc_update_firewall(self, context, firewall_id):
        status_update = {"firewall": {"status": const.PENDING_UPDATE}}
        super(HuaweiFWAASDriverPlugin, self).update_firewall(context,
                                                             firewall_id,
                                                             status_update)
        fw_with_rules = self._make_firewall_dict_with_rules(context,
                                                            firewall_id)
        # this is triggered on an update to fw rule or policy, no
        # change in associated routers.
        fw_with_rules['add-router-ids'] = self.get_firewall_routers(
                context, firewall_id)
        fw_with_rules['del-router-ids'] = []
        self.agent_rpc.update_firewall(context, fw_with_rules)

    def _rpc_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._rpc_update_firewall(context, firewall_id)

    def _ensure_update_firewall(self, context, firewall_id):
        fwall = self.get_firewall(context, firewall_id)
        if fwall['status'] in [const.PENDING_CREATE,
                               const.PENDING_UPDATE,
                               const.PENDING_DELETE]:
            raise fw_ext.FirewallInPendingState(firewall_id=firewall_id,
                                                pending_state=fwall['status'])

    def _ensure_update_firewall_policy(self, context, firewall_policy_id):
        firewall_policy = self.get_firewall_policy(context, firewall_policy_id)
        if firewall_policy and 'firewall_list' in firewall_policy:
            for firewall_id in firewall_policy['firewall_list']:
                self._ensure_update_firewall(context, firewall_id)

    def _ensure_update_firewall_rule(self, context, firewall_rule_id):
        fw_rule = self.get_firewall_rule(context, firewall_rule_id)
        if 'firewall_policy_id' in fw_rule and fw_rule['firewall_policy_id']:
            self._ensure_update_firewall_policy(context,
                                                fw_rule['firewall_policy_id'])

    def _get_routers_for_create_firewall(self, tenant_id, context, firewall):

        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        if router_ids == attr.ATTR_NOT_SPECIFIED:
            # old semantics router-ids keyword not specified pick up
            # all routers on tenant.
            l3_plugin = manager.NeutronManager.get_service_plugins().get(
                const.L3_ROUTER_NAT)
            ctx = neutron_context.get_admin_context()
            routers = l3_plugin.get_routers(ctx)
            router_ids = [
                router['id']
                for router in routers
                if router['tenant_id'] == tenant_id]
            # validation can still fail this if there is another fw
            # which is associated with one of these routers.
            self.validate_firewall_routers_not_in_use(context, router_ids)
            return router_ids
        else:
            if not router_ids:
                # This indicates that user specifies no routers.
                return []
            else:
                # some router(s) provided.
                self.validate_firewall_routers_not_in_use(context, router_ids)
                return router_ids

    def delete_db_firewall_object(self, context, id):
        firewall = self.get_firewall(context, id)
        if firewall['status'] == const.PENDING_DELETE:
            super(HuaweiFWAASDriverPlugin, self).delete_firewall(context, id)

#    def insert_rule(self, context, id, rule_info):
#        LOG.debug("insert_rule() called")
#        self._ensure_update_firewall_policy(context, id)
#        fwp = super(FirewallPlugin,
#                    self).insert_rule(context, id, rule_info)
#        self._rpc_update_firewall_policy(context, id)
#        return fwp

#    def remove_rule(self, context, id, rule_info):
#        LOG.debug("remove_rule() called")
#        self._ensure_update_firewall_policy(context, id)
#        fwp = super(FirewallPlugin,
#                    self).remove_rule(context, id, rule_info)
#        self._rpc_update_firewall_policy(context, id)
#        return fwp

    def get_firewalls(self, context, filters=None, fields=None):
        LOG.debug("fwaas get_firewalls() called")
        fw_list = super(HuaweiFWAASDriverPlugin, self).get_firewalls(
                        context, filters, fields)
        for fw in fw_list:
            fw_current_rtrs = self.get_firewall_routers(context, fw['id'])
            fw['router_ids'] = fw_current_rtrs
        return fw_list

    def get_firewall(self, context, id, fields=None):
        LOG.debug("fwaas get_firewall() called")
        res = super(HuaweiFWAASDriverPlugin, self).get_firewall(
                        context, id, fields)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        res['router_ids'] = fw_current_rtrs
        return res

    def create_firewall(self, context, firewall):
        LOG.debug("create_firewall() called")
        LOG.debug("firewall_type:%s" % firewall)
        tenant_id = self._get_tenant_id_for_create(context,
                                                   firewall['firewall'])

        fw_new_rtrs = self._get_routers_for_create_firewall(
            tenant_id, context, firewall)

        LOG.debug("router_id: %s", fw_new_rtrs)
        LOG.debug("firewall: %s", firewall)
        LOG.debug("tenant_id: %s", tenant_id)

        if not fw_new_rtrs:
            # no messaging to agent needed, and fw needs to go
            # to INACTIVE(no associated rtrs) state.
            status = const.ACTIVE
            fw = super(HuaweiFWAASDriverPlugin, self).create_firewall(
                context, firewall, status)
            fw['router_ids'] = []
            LOG.info("AC:process_create_firewall")
            LOG.info("fw:%s", fw)
            rest_info = {}
            fwall = {}
            fwall['id'] = fw['id']
            fwall['tenantId'] = fw['tenant_id']
            fwall['name'] = fw['name']
            fwall['description'] = fw['description']
            fwall['adminStateUp'] = fw['admin_state_up']
            fwall['shared'] = fw['shared']
            fwall['firewallPolicyId'] = fw['firewall_policy_id']
            fwall['routerIds'] = fw_new_rtrs
            rest_info['firewall'] = fwall
            try:
                self.__restRequest__(fw['id'], rest_info,
                                     OperationType.CREATE_FIREWALL)
            except Exception:
                super(HuaweiFWAASDriverPlugin, self).\
                    delete_firewall(context, fw['id'])
                LOG.info('ERROR')
                raise Exception

            return fw
        else:
            status = const.ACTIVE
            fw = super(HuaweiFWAASDriverPlugin, self).create_firewall(
                context, firewall, status)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (self._make_firewall_dict_with_rules(context,
                                                             fw['id']))

        fw_with_rtrs = {'fw_id': fw['id'],
                        'router_ids': fw_new_rtrs}
        self.set_routers_for_firewall(context, fw_with_rtrs)
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = []
        LOG.info("AC:process_create_firewall")
        LOG.info("fw:%s", fw)
        rest_info = {}
        fwall = {}
        fwall['id'] = fw['id']
        fwall['tenantId'] = fw['tenant_id']
        fwall['name'] = fw['name']
        fwall['description'] = fw['description']
        fwall['adminStateUp'] = fw['admin_state_up']
        fwall['shared'] = fw['shared']
        fwall['firewallPolicyId'] = fw['firewall_policy_id']
        fwall['routerIds'] = fw_new_rtrs
        rest_info['firewall'] = fwall
        try:
            self.__restRequest__(fw['id'], rest_info,
                                 OperationType.CREATE_FIREWALL)
        except Exception:
            super(HuaweiFWAASDriverPlugin, self).\
                delete_firewall(context, fw['id'])
            LOG.info('ERROR')
            raise Exception
        # self.agent_rpc.create_firewall(context, fw_with_rules)
        return fw

    def update_firewall(self, context, id, firewall):
        LOG.debug("update_firewall() called")

        self._ensure_update_firewall(context, id)
        # pop router_id as this goes in the router association db
        # and not firewall db
        router_ids = firewall['firewall'].pop('router_ids', None)
        fw_current_rtrs = self.get_firewall_routers(context, id)
        if router_ids is not None:
            if router_ids == []:
                # This indicates that user is indicating no routers.
                fw_new_rtrs = []
            else:
                self.validate_firewall_routers_not_in_use(
                    context, router_ids, id)
                fw_new_rtrs = router_ids
            self.update_firewall_routers(context, {'fw_id': id,
                                                   'router_ids': fw_new_rtrs})
        else:
            # router-ids keyword not specified for update pick up
            # existing routers.
            fw_new_rtrs = self.get_firewall_routers(context, id)

        LOG.info("AC:process_update_firewall")
        LOG.debug('fw_new_rtrs:%s', fw_new_rtrs)
        LOG.info("firewall:%s", firewall)
        fw = firewall['firewall']
        rest_info = {}
        firewall_ac = {}
        firewall_ac['id'] = id
        if 'name' in fw:
            firewall_ac['name'] = fw['name']
        if 'description' in fw:
            firewall_ac['description'] = fw['description']
        if 'adminStateUp' in fw:
            firewall_ac['adminStateUp'] = fw['admin_state_up']
        if 'firewallPolicyId' in fw:
            firewall_ac['firewallPolicyId'] = fw['firewall_policy_id']

        firewall_ac['routerIds'] = fw_new_rtrs
        rest_info['firewall'] = firewall_ac
        self.__restRequest__(id, rest_info, OperationType.UPDATE_FIREWALL)

        if not fw_new_rtrs and not fw_current_rtrs:
            # no messaging to agent needed, and we need to continue
            # in INACTIVE state
            firewall['firewall']['status'] = const.ACTIVE
            fw = super(HuaweiFWAASDriverPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = []
            return fw
        else:
            firewall['firewall']['status'] = const.ACTIVE
            fw = super(HuaweiFWAASDriverPlugin, self).update_firewall(
                context, id, firewall)
            fw['router_ids'] = fw_new_rtrs

        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))

        # determine rtrs to add fw to and del from
        fw_with_rules['add-router-ids'] = fw_new_rtrs
        fw_with_rules['del-router-ids'] = list(
            set(fw_current_rtrs).difference(set(fw_new_rtrs)))

        # last-router drives agent to ack with status to set state to INACTIVE
        fw_with_rules['last-router'] = not fw_new_rtrs

        LOG.debug("update_firewall(): Add Routers: %s, Del Routers: %s",
                  fw_with_rules['add-router-ids'],
                  fw_with_rules['del-router-ids'])

        # self.agent_rpc.update_firewall(context, fw_with_rules)

        return fw

    def delete_firewall(self, context, id):
        LOG.debug("delete_firewall() called")
        LOG.info("AC:process_delete_firewall")
        self.__restRequest__(id, None, OperationType.DELETE_FIREWALL)
        status_update = {"firewall": {"status": const.PENDING_DELETE}}
        fw = super(HuaweiFWAASDriverPlugin, self).\
            update_firewall(context, id, status_update)
        fw_with_rules = (
            self._make_firewall_dict_with_rules(context, fw['id']))
        fw_with_rules['del-router-ids'] = self.get_firewall_routers(
            context, id)
        fw_with_rules['add-router-ids'] = []
        # if not fw_with_rules['del-router-ids']:
        # no routers to delete on the agent side
        self.delete_db_firewall_object(context, id)
        # else:
        # self.agent_rpc.delete_firewall(context, fw_with_rules)

    def get_firewall_rules(self, context, filters=None, fields=None):
        LOG.info('filters:%s' % filters)
        LOG.info('fields:%s' % fields)
        return super(HuaweiFWAASDriverPlugin, self).\
            get_firewall_rules(context, filters, fields)

    def create_firewall_rule(self, context, firewall_rule):
        LOG.debug(("create_firewall_rule() called"))
        LOG.debug("firewall_rule_type:%s" % firewall_rule)
        fwrDb = super(HuaweiFWAASDriverPlugin, self).\
            create_firewall_rule(context, firewall_rule)
        LOG.info(("AC:process_create_firewall_rule"))
        LOG.debug("create_firewall_rule \
         firewall_rule is %s", fwrDb)
        fwr = firewall_rule['firewall_rule']
        rest_info = {}
        firewallRule = {}
        firewallRule['id'] = fwrDb['id']
        firewallRule['tenantId'] = fwrDb['tenant_id']
        firewallRule['name'] = fwrDb['name']
        firewallRule['description'] = fwrDb['description']
        firewallRule['firewallPolicyId'] = fwrDb['firewall_policy_id']
        firewallRule['shared'] = fwrDb['shared']
        firewallRule['protocol'] = fwr['protocol']
        firewallRule['ipVersion'] = fwrDb['ip_version']
        firewallRule['sourceIpAddress'] = fwrDb['source_ip_address']
        firewallRule['destinationIpAddress'] = fwrDb['destination_ip_address']
        firewallRule['sourcePort'] = fwrDb['source_port']
        firewallRule['destinationPort'] = fwrDb['destination_port']
        firewallRule['position'] = fwrDb['position']
        firewallRule['action'] = fwrDb['action']
        firewallRule['enabled'] = fwrDb['enabled']
        rest_info['firewallRule'] = firewallRule
        try:
            self.__restRequest__(None, rest_info,
                                 OperationType.CREATE_FIREWALL_RULE)
        except Exception:
            super(HuaweiFWAASDriverPlugin, self).\
                delete_firewall_rule(context, fwrDb['id'])
            LOG.info('ERROR')
            raise Exception
        return fwrDb

    def update_firewall_rule(self, context, id, firewall_rule):
        LOG.debug("update_firewall_rule() called")
        LOG.info(("AC:process_update_firewall_rule"))
        LOG.debug("update_firewall_rule \
        rule_info is %s", firewall_rule)
        fwr = firewall_rule['firewall_rule']
        rest_info = {}
        firewallRule = {}
        firewallRule['id'] = id
        firewallRule['name'] = fwr['name']
        firewallRule['description'] = fwr['description']
        if 'protocol' in fwr and fwr['protocol'] is not None:
            firewallRule['protocol'] = fwr['protocol']
        else:
            firewallRule['protocol'] = "Any"
        firewallRule['action'] = fwr['action']
        if 'source_ip_address'in fwr and fwr['source_ip_address'] is not None:
            firewallRule['sourceIpAddress'] = fwr['source_ip_address']
        else:
            firewallRule['sourceIpAddress'] = ''

        if 'destination_ip_address' in fwr \
                and fwr['destination_ip_address'] is not None:
            firewallRule['destinationIpAddress'] = \
                fwr['destination_ip_address']
        else:
            firewallRule['destinationIpAddress'] = ''

        if 'source_port' in fwr and fwr['source_port'] is not None:
            firewallRule['sourcePort'] = fwr['source_port']
        else:
            firewallRule['sourcePort'] = ''

        if 'destination_port' in fwr and fwr['destination_port'] is not None:
            firewallRule['destinationPort'] = fwr['destination_port']
        else:
            firewallRule['destinationPort'] = ''
        firewallRule['shared'] = fwr['shared']
        firewallRule['enabled'] = fwr['enabled']
        firewallRule['ipVersion'] = '4'
        rest_info['firewallRule'] = firewallRule
        self.__restRequest__(id, rest_info, OperationType.UPDATE_FIREWALL_RULE)

        self._ensure_update_firewall_rule(context, id)
        fwr = super(HuaweiFWAASDriverPlugin, self).\
            update_firewall_rule(context, id, firewall_rule)
#        firewall_policy_id = fwr['firewall_policy_id']
#        if firewall_policy_id:
#            self._rpc_update_firewall_policy(context, firewall_policy_id)
        return fwr

    def delete_firewall_rule(self, context, id):
        LOG.debug(("delete_firewall_rule() called"))
        LOG.info(("AC:process_delete_firewall_rule"))
        self.__restRequest__(id, None, OperationType.DELETE_FIREWALL_RULE)
        super(HuaweiFWAASDriverPlugin, self).delete_firewall_rule(context, id)

    def create_firewall_policy(self, context, firewall_policy):
        LOG.debug(("create_firewall_policy() called"))
        LOG.debug("firewall_policy:%s" % firewall_policy)
        fwpDb = super(HuaweiFWAASDriverPlugin, self).\
            create_firewall_policy(context, firewall_policy)
        LOG.info(("AC:process_create_firewall_policy"))
        LOG.debug("create_firewall_policy \
         firewall_policy is %s", fwpDb)
        rest_info = {}
        firewallPolicy = {}
        firewallPolicy['id'] = fwpDb['id']
        firewallPolicy['tenantId'] = fwpDb['tenant_id']
        firewallPolicy['name'] = fwpDb['name']
        firewallPolicy['description'] = fwpDb['description']
        firewallPolicy['firewallrules'] = fwpDb['firewall_rules']
        firewallPolicy['shared'] = fwpDb['shared']
        firewallPolicy['audited'] = fwpDb['audited']
        firewallPolicy['publicIpEnable'] = True
        rest_info['firewallPolicy'] = firewallPolicy
        try:
            self.__restRequest__(fwpDb['id'], rest_info,
                                 OperationType.CREATE_FIREWALL_POLICY)
        except Exception:
            super(HuaweiFWAASDriverPlugin, self).\
                delete_firewall_policy(context, fwpDb['id'])
            LOG.info('ERROR')
            raise Exception
        return fwpDb

    def delete_firewall_policy(self, context, id):
        LOG.debug(("delete_firewall_policy() called"))
        LOG.info(("AC:process_delete_firewall_policy"))
        self.__restRequest__(id, None, OperationType.DELETE_FIREWALL_POLICY)
        super(HuaweiFWAASDriverPlugin, self).\
            delete_firewall_policy(context, id)

    def update_firewall_policy(self, context, id, firewall_policy):
        LOG.debug(("update_firewall_policy() called"))
        LOG.info(("AC:process_update_firewall_policy"))
        LOG.debug("update_firewall_policy \
        fwp is %s", firewall_policy['firewall_policy'])
        fwp = firewall_policy['firewall_policy']
        rest_info = {}
        firewallPolicy = {}
        firewallPolicy['shared'] = fwp['shared']
        firewallPolicy['description'] = fwp['description']
        firewallPolicy['name'] = fwp['name']
        firewallPolicy['audited'] = fwp['audited']
        firewallPolicy['publicIpEnable'] = True
        rest_info['firewallPolicy'] = firewallPolicy
        self.__restRequest__(id, rest_info, OperationType.
                             UPDATE_FIREWALL_POLICY)
        self._ensure_update_firewall_policy(context, id)
        fwpDb = super(HuaweiFWAASDriverPlugin, self).\
            update_firewall_policy(context, id, firewall_policy)
        # self._rpc_update_firewall_policy(context, id)
        return fwpDb

    def insert_rule(self, context, id, rule_info):
        LOG.info(("AC:process_insert_rule"))
        LOG.debug("firewall_policy_id:%s", id)
        LOG.debug("rule_info:%s", rule_info)
        rest_info = {}
        if 'insert_before' in rule_info \
                and rule_info['insert_before'] != '':
            rest_info['insertBefore'] = rule_info['insert_before']
        if 'insert_after' in rule_info \
                and rule_info['insert_after'] != '' \
                and rule_info['insert_before'] == '':
            rest_info['insertAfter'] = rule_info['insert_after']
        rest_info['firewallRuleId'] = rule_info['firewall_rule_id']
        rest_info['id'] = id
        """openstack default is insert first but AC default is
         last so here need to do adapt"""
        if not rule_info['insert_before'] and not rule_info['insert_after']:
            firewall_rule = super(HuaweiFWAASDriverPlugin, self).\
                get_firewall_rule(context, rule_info['firewall_rule_id'])
            LOG.info('firewall_rule:%s' % firewall_rule)
            filters = {}
            filters['firewall_policy_id'] = [id]
            filters['position'] = ['1']
            firewall_rules = self.get_firewall_rules(context, filters, None)
            if len(firewall_rules) > 0:
                LOG.info('firewall_rule_first:%s' % firewall_rules)
                firewall_rule_first = firewall_rules[0]
                rest_info['insertBefore'] = firewall_rule_first['id']

        self.__restRequest__(id, rest_info, OperationType.INSERT_FIREWALL_RULE)
        return super(HuaweiFWAASDriverPlugin, self).\
            insert_rule(context, id, rule_info)

    def remove_rule(self, context, id, rule_info):
        LOG.info(("AC:process_remove_rule"))
        LOG.debug("firewall_policy_id:%s", id)
        LOG.debug("rule_info:%s", rule_info)
        rest_info = {}
        rest_info['firewallRuleId'] = rule_info['firewall_rule_id']
        rest_info['id'] = id
        self.__restRequest__(id, rest_info, OperationType.REMOVE_FIREWALL_RULE)
        return super(HuaweiFWAASDriverPlugin, self).\
            remove_rule(context, id, rule_info)

    def __restRequest__(self, id, entry_info, operation):

        LOG.debug(("the entry_info is %s"), entry_info)
        LOG.debug(("the id is %s"), id)
        service = RESTService()
        isNeedServiceName = False
#         entry_info['neutron_name'] = service.config["neutron_name"]

        if operation == OperationType.CREATE_FIREWALL:
            serviceName = 'create_firewall'
            url = "/controller/dc/esdk/v2.0/firewalls"
            methodName = 'POST'
        elif operation == OperationType.DELETE_FIREWALL:
            serviceName = 'delete_firewall'
            url = "/controller/dc/esdk/v2.0/firewalls"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_FIREWALL:
            serviceName = 'update_firewall'
            url = "/controller/dc/esdk/v2.0/firewalls"
            methodName = 'PUT'
        elif operation == OperationType.CREATE_FIREWALL_POLICY:
            serviceName = 'create_firewall_policy'
            url = "/controller/dc/esdk/v2.0/firewallpolicys"
            methodName = 'POST'
        elif operation == OperationType.DELETE_FIREWALL_POLICY:
            serviceName = 'delete_firewall_policy'
            url = "/controller/dc/esdk/v2.0/firewallpolicys"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_FIREWALL_POLICY:
            serviceName = 'update_firewall_policy'
            url = "/controller/dc/esdk/v2.0/firewallpolicys"
            methodName = 'PUT'
        elif operation == OperationType.CREATE_FIREWALL_RULE:
            serviceName = 'create_firewall_rule'
            url = "/controller/dc/esdk/v2.0/firewallrules"
            methodName = 'post'
        elif operation == OperationType.DELETE_FIREWALL_RULE:
            serviceName = 'delete_firewall_rule'
            url = "/controller/dc/esdk/v2.0/firewallrules"
            methodName = 'DELETE'
        elif operation == OperationType.UPDATE_FIREWALL_RULE:
            serviceName = 'update_firewall_rule'
            url = "/controller/dc/esdk/v2.0/firewallrules"
            methodName = 'PUT'
        elif operation == OperationType.INSERT_FIREWALL_RULE:
            serviceName = 'insert_firewall_rule'
            url = "/controller/dc/esdk/v2.0/firewallpolicys/insert_rule"
            methodName = 'PUT'
        elif operation == OperationType.REMOVE_FIREWALL_RULE:
            serviceName = 'remove_firewall_rule'
            url = "/controller/dc/esdk/v2.0/firewallpolicys/remove_rule"
            methodName = 'PUT'
        else:
            LOG.debug(("the operation is wrong"))

        LOG.debug(("the serviceName is: %s"), serviceName)
        LOG.debug(("the ac_data is: %s"), json.dumps(entry_info))
        service.requestService(methodName, url, id, entry_info,
                               isNeedServiceName, self.__callBack__)

    def __callBack__(self, errorCode, reason, status, data=None):
        LOG.info("restRequest success")
        LOG.debug(("the reason is: %s"), reason)
        LOG.debug(("the errorCode is: %s"), errorCode)
        LOG.debug(("the status is: %s"), status)
        LOG.debug(("the data is: %s"), data)

        if status == 200 and reason is None:
            if errorCode != '0':
                LOG.debug(("raise MechanismDriverError"))
                raise Exception
        elif status == 204:
            pass
        else:
            LOG.debug(("raise MechanismDriverError"))
    raise Exception
