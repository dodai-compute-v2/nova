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
        instance_type = filter_properties.get('instance_type')
        bm_node_uuid = host_state.nodename
        context = filter_properties['context'].elevated()
        try:
            bm_node = bmdb.bm_node_get_by_node_uuid(context, bm_node_uuid)
            instance_type_id = bm_node['instance_type_id']
            return instance_type_id == int(instance_type['flavorid'])
        except Exception as e:
            LOG.warn(str(e))
            return False


class DodaiRamFilter(ram_filter.RamFilter):
    """DodaiRamFilter passes the non-tasked nodes with sufficient available RAM
       and the resource pool's nodes(i.e. the running nodes with admin owner).

       NOTE: Only non-admin user can use resource pool's nodes.
             Admin user can use non-tasked nodes outside resource pool.
    """

    def host_passes(self, host_state, filter_properties):
        bm_node_uuid = host_state.nodename
        context = filter_properties['context'].elevated()
        try:
            bm_node = bmdb.bm_node_get_by_node_uuid(context, bm_node_uuid)
            task_state = bm_node['task_state']
            resource_pool = bm_node['resource_pool']
        except Exception as e:
            LOG.warn(str(e))
            return False

        request_spec = filter_properties['request_spec']
        instance_properties = request_spec['instance_properties']
        user_id = instance_properties.get('user_id')
        project_id = instance_properties.get('project_id')
        is_resource_pool_user = _instance_spawned_by_resource_pool_user(
                                        user_id, project_id)
        if is_resource_pool_user:
            if task_state in (states.NULL, states.INIT):
                return super(DodaiRamFilter,
                             self).host_passes(host_state, filter_properties)
        else:
            if task_state == states.ACTIVE and resource_pool:
                # active host in resource pool
                return True
        return False


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
