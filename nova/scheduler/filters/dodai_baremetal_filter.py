# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 National Institute of Informatics.
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

from oslo.config import cfg

from keystoneclient.v2_0 import client as keystone_client

from nova.openstack.common import log as logging
from nova.scheduler import filters
from nova.scheduler.filters import core_filter
from nova.scheduler.filters import disk_filter
from nova.scheduler.filters import ram_filter
from nova.virt.baremetal import baremetal_states as states
from nova.virt.baremetal import db as bmdb


LOG = logging.getLogger(__name__)

baremetal_opts = [
    cfg.ListOpt('resource_pool_usernames',
                default=[],
                help="The name list that identifies users who can operate "
                     "resource pool."),
]

keystone_opts = [
    cfg.StrOpt('username', help=_("Keystone user")),
    cfg.StrOpt('password', help=_("Keystone password"), secret=True),
    cfg.StrOpt('tenant_name', help=_("Admin tenant name")),
    cfg.StrOpt('auth_url', help=_("Authentication URL")),
]

CONF = cfg.CONF
CONF.register_opts(baremetal_opts, 'baremetal')
CONF.register_opts(keystone_opts, 'keystone')


class DodaiInstanceTypeFilter(filters.BaseHostFilter):
    """DodaiInstanceTypeFilter passes the host,
       which instance_type_id matches the requested one.
    """

    def host_passes(self, host_state, filter_properties):
        LOG.debug("#DodaiInstanceTypeFilter.host_passes() called.")
        instance_type = filter_properties.get('instance_type')
        bm_node_uuid = host_state.nodename
        context = filter_properties['context'].elevated()
        try:
            bm_node = bmdb.bm_node_get_by_node_uuid(context, bm_node_uuid)
            instance_type_id = bm_node['instance_type_id']
            result = (instance_type_id == int(instance_type['flavorid']))
            LOG.debug("#DodaiInstanceTypeFilter instance_type_id=%s"
                      % instance_type_id)
            LOG.debug("#DodaiInstanceTypeFilter flavorid=%s"
                      % instance_type['flavorid'])
            LOG.debug("#DodaiInstanceTypeFilter result=%s" % result)
            return result
        except Exception as e:
            LOG.warn(str(e))
            return False


class DodaiResourcePoolFilter(filters.BaseHostFilter):
    """DodaiResourcePoolFilter passes the non-tasked nodes with
       sufficient available RAM and the resource pool's nodes.
    """

    def host_passes(self, host_state, filter_properties):
        LOG.debug("#DodaiRamFilter.host_passes() called.")
        bm_node_uuid = host_state.nodename
        context = filter_properties['context'].elevated()
        try:
            bm_node = bmdb.bm_node_get_by_node_uuid(context, bm_node_uuid)
            task_state = bm_node['task_state']
            resource_pool = bm_node['resource_pool']
            LOG.debug("#DodaiResourcePoolFilter bm_node=%s" % bm_node)
        except Exception as e:
            LOG.warn(str(e))
            return False

        request_spec = filter_properties['request_spec']
        instance_properties = request_spec['instance_properties']
        user_id = instance_properties.get('user_id')
        project_id = instance_properties.get('project_id')
        LOG.debug("#DodaiResourcePoolFilter user_id=%s" % user_id)
        LOG.debug("#DodaiResourcePoolFilter project_id=%s" % project_id)
        is_resource_pool_user = _instance_spawned_by_resource_pool_user(
                                        user_id, project_id)
        LOG.debug("#DodaiResourcePoolFilter is_resource_pool_user=%s"
                  % is_resource_pool_user)
        result = False
        # NOTE(yokose): Resource-pool user can use non-tasked nodes outside
        #               resource pool.
        #               Non-resource-pool user can use resource pool's nodes.
        if is_resource_pool_user:
            if task_state in (states.NULL, states.INIT):
                LOG.debug("This host represents non-tasked node outside "
                          "resource pool.")
                core_result = core_filter.CoreFilter().host_passes(
                                  host_state, filter_properties)
                LOG.debug("#DodaiResourcePoolFilter core_result=%s"
                          % core_result)
                disk_result = disk_filter.DiskFilter().host_passes(
                                  host_state, filter_properties)
                LOG.debug("#DodaiResourcePoolFilter disk_result=%s"
                          % disk_result)
                ram_result = ram_filter.RamFilter().host_passes(
                                 host_state, filter_properties)
                LOG.debug("#DodaiResourcePoolFilter ram_result=%s"
                          % ram_result)
                result = core_result and disk_result and ram_result
        else:
            if task_state == states.ACTIVE and resource_pool:
                LOG.debug("This host represents active node in resource pool.")
                # clear oversubscription limit for compute node to test against
                host_state.limits['vcpu'] = None
                host_state.limits['disk_gb'] = None
                host_state.limits['memory_mb'] = None
                result = True
        LOG.debug("#DodaiResourcePoolFilter result=%s" % result)
        return result


def _instance_spawned_by_resource_pool_user(user_id, project_id):
    try:
        kc = keystone_client.Client(
                 username=CONF.keystone.username,
                 password=CONF.keystone.password,
                 tenant_name=CONF.keystone.tenant_name,
                 auth_url=CONF.keystone.auth_url)
        roles = kc.users.list_roles(user_id, project_id)
        user = kc.users.get(user_id)
    except Exception as e:
        LOG.warn(str(e))
        return False

    return ('admin' in [role.name for role in roles] and
            user.name in CONF.baremetal.resource_pool_usernames)
