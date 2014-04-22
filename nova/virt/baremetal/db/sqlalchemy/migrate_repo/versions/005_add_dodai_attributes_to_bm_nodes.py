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

from sqlalchemy import Column, MetaData, String, Integer, Boolean, Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    t = Table('bm_nodes', meta, autoload=True)
    host_name = Column('host_name', String(255))
    instance_type_id = Column('instance_type_id', Integer)
    prov_ip_address = Column('prov_ip_address', String(255))
    ipmi_interface = Column('ipmi_interface', String(255))
    ipmitool_extra_option = Column('ipmitool_extra_option', String(255))
    kernel_append_params = Column('kernel_append_params', String(255))
    resource_pool = Column('resource_pool', Boolean)
    for c in [host_name, instance_type_id, prov_ip_address, ipmi_interface,
              ipmitool_extra_option, kernel_append_params, resource_pool]:
        t.create_column(c)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    t = Table('bm_nodes', meta, autoload=True)
    t.drop_column('instance_name')
    for c in ['host_name', 'instance_type_id', 'prov_ip_address',
              'ipmi_interface', 'ipmitool_extra_option',
              'kernel_append_params', 'resource_pool']:
        t.drop_column(c)
