# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 Hewlett-Packard Development Company, L.P.
# Copyright (c) 2012 NTT DOCOMO, INC.
# Copyright 2013 National Institute of Informatics.
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

"""
Class for PXE bare-metal nodes.
"""

import datetime
import os
import socket
import httplib2
import tempfile
import shutil
import commands

from oslo.config import cfg

from nova.compute import instance_types
from nova import exception
from nova.openstack.common import fileutils
from nova.openstack.common import importutils
from nova.openstack.common import log as logging
from nova.openstack.common import timeutils
from nova import utils
from nova.virt.baremetal import baremetal_states
from nova.virt.baremetal import base
from nova.virt.baremetal import db
from nova.virt.baremetal import utils as bm_utils

pxe_opts = [
    cfg.StrOpt('deploy_kernel',
               help='Default kernel image ID used in deployment phase'),
    cfg.StrOpt('deploy_ramdisk',
               help='Default ramdisk image ID used in deployment phase'),
    cfg.StrOpt('pxe_append_params',
               help='additional append parameters for baremetal PXE boot'),
    cfg.StrOpt('pxe_config_template',
               default='$pybasedir/nova/virt/baremetal/dodai_pxe_config.'
                       'template',
               help='Template file for PXE configuration'),
    cfg.IntOpt('pxe_deploy_timeout',
               help='Timeout for PXE deployments. Default: 0 (unlimited)',
               default=0),
    cfg.IntOpt('pxe_deploy_check_timeout',
               help='Timeout for PXE deployments check request.',
               default=500),
    cfg.IntOpt('pxe_deploy_check_interval',
               help='Interval for PXE deployments check request.',
               default=5),
    cfg.StrOpt('injection_scripts_path',
               default='/var/lib/nova/baremetal/injection-scripts',
               help='Path of injection scripts to be used when deploying'),
    cfg.StrOpt('deletion_scripts_path',
               default='/var/lib/nova/baremetal/deletion-scripts',
               help='Path of disk deletion scripts to be used when deleting'),
    cfg.StrOpt('base_dir_path',
               default='/var/lib/nova/instances/_base/',
               help="Where cached images are stored under $instances_path."
                    "This is NOT the full path - just a folder name."
                    "For per-compute-host cached images, set to _base_$my_ip"),
    cfg.StrOpt('os_install_manager',
               default='nova.virt.baremetal.dodai_os_install_manager.'
                       'DodaiOSInstallManager',
               help="Call the dodai_os_install_manager.py"),
    cfg.IntOpt('dodai_instance_agent_bind_port',
               default=60601,
               help='Port number that is used when the deploying'),
    cfg.IntOpt('dodai_instance_agent_bind_subport',
               default=60602,
               help='Port number that is used when the deploying'),
    cfg.StrOpt('dodai_instance_agent_config',
               default='/mnt/.dodai/etc',
               help='Config path that is used when the deploying'),
    cfg.StrOpt('dodai_prov_subnet',
               help='Subnet address that is used when the deploying'),
]

LOG = logging.getLogger(__name__)

baremetal_group = cfg.OptGroup(name='baremetal',
                               title='Baremetal Options')

CONF = cfg.CONF
CONF.register_group(baremetal_group)
CONF.register_opts(pxe_opts, baremetal_group)
CONF.import_opt('use_ipv6', 'nova.netconf')

CHEETAH = None


def _get_cheetah():
    global CHEETAH
    if CHEETAH is None:
        from Cheetah import Template
        CHEETAH = Template.Template
    return CHEETAH


def build_pxe_config(deployment_aki_path, deployment_ari_path,
                     root_size, swap_size, ephemeral_size,
                     kdump_size, ami_path, prov_ip_address,
                     prov_mac_address, host_name,
                     root_fs_type, is_delete=False):
    pxe_options = {
        'deployment_aki_path': deployment_aki_path,
        'deployment_ari_path': deployment_ari_path,
        'root_size': root_size,
        'swap_size': swap_size,
        'ephemeral_size': ephemeral_size,
        'kdump_size': kdump_size,
        'ami_path': ami_path,
        'prov_ip_address': prov_ip_address,
        'prov_mac_address': prov_mac_address,
        'host_name': host_name,
        'root_fs_type': root_fs_type,
        'agent_bind_port': CONF.baremetal.dodai_instance_agent_bind_port,
        'agent_bind_subport': CONF.baremetal.dodai_instance_agent_bind_subport,
        'agent_config': CONF.baremetal.dodai_instance_agent_config,
        'prov_subnet': CONF.baremetal.dodai_prov_subnet,
        'pxe_append_params': CONF.baremetal.pxe_append_params,
    }
    if is_delete:
        pxe_options.update({
            'action': 'delete',
            'deletion_scripts_path': CONF.baremetal.deletion_scripts_path,
            'injection_scripts_path': ''})
    else:
        pxe_options.update({
            'action': 'deploy',
            'deletion_scripts_path': '',
            'injection_scripts_path': CONF.baremetal.injection_scripts_path})
    cheetah = _get_cheetah()
    pxe_config = str(cheetah(
        open(CONF.baremetal.pxe_config_template).read(),
        searchList=[{'pxe_options': pxe_options,
                     'ROOT': '${ROOT}'}]))
    return pxe_config


def get_deploy_aki_id(instance_type):
    return instance_type.get('extra_specs', {}).\
        get('baremetal:deploy_kernel_id', CONF.baremetal.deploy_kernel)


def get_deploy_ari_id(instance_type):
    return instance_type.get('extra_specs', {}).\
        get('baremetal:deploy_ramdisk_id', CONF.baremetal.deploy_ramdisk)


def get_image_dir_path(instance):
    """Generate the dir for an instances disk."""
    return os.path.join(CONF.instances_path, instance['name'])


def get_image_file_path(instance):
    """Generate the full path for an instances disk."""
    return os.path.join(CONF.instances_path, instance['name'], 'disk')


def get_pxe_config_file_path(instance):
    """Generate the path for an instances PXE config file."""
    return os.path.join(CONF.baremetal.tftp_root, instance['uuid'], 'config')


def get_root_fs_type(instance, image_path):
    file_type = commands.getoutput(" ".join(["file", "-b", image_path]))

    if file_type.find("ext2") != -1:
        return "ext2"
    elif file_type.find("ext3") != -1:
        return "ext3"
    elif file_type.find("ext4") != -1:
        return "ext4"
    elif file_type.find("btrfs") != -1:
        return "btrfs"
    elif file_type.find("reiserfs") != -1:
        return "reiserfs"
    elif file_type.find("jfs2") != -1:
        return "jfs2"
    elif file_type.find("xfs") != -1:
        return "xfs"
    else:
        return "ext2"


def get_partition_sizes(instance, instance_type):
    instance_type_ex = instance_types.extract_instance_type(instance)
    root_mb = instance_type_ex['root_gb'] * 1024
    swap_mb = instance_type_ex['swap'] * 1024
    ephemeral_mb = instance_type_ex['ephemeral_gb'] * 1024
    kdump_mb = instance_type.get('extra_specs', {}).\
        get('baremetal:kdump_gb', 0)
    kdump_mb = int(kdump_mb) * 1024

    return (root_mb, swap_mb, ephemeral_mb, kdump_mb)


def get_pxe_mac_path(mac):
    """Convert a MAC address into a PXE config file name."""
    return os.path.join(
        CONF.baremetal.tftp_root,
        'pxelinux.cfg',
        "01-" + mac.replace(":", "-").lower()
    )


def get_tftp_image_info(instance, instance_type):
    """Generate the paths for tftp files for this instance

    Raises NovaException if
    - instance does not contain kernel_id or ramdisk_id
    - deploy_kernel_id or deploy_ramdisk_id can not be read from
      instance_type['extra_specs'] and defaults are not set

    """
    image_info = {
        'deploy_kernel': [None, None],
        'deploy_ramdisk': [None, None],
        'image_ref': [None, None],
    }
    try:
        image_info['deploy_kernel'][0] = get_deploy_aki_id(instance_type)
        image_info['deploy_ramdisk'][0] = get_deploy_ari_id(instance_type)
        image_info['image_ref'][0] = instance['image_ref']
    except KeyError as e:
        pass

    missing_labels = []
    image_info['deploy_kernel'][1] = os.path.join(
        CONF.baremetal.base_dir_path, image_info['deploy_kernel'][0])
    image_info['deploy_ramdisk'][1] = os.path.join(
        CONF.baremetal.base_dir_path, image_info['deploy_ramdisk'][0])
    image_info['image_ref'][1] = os.path.join(
        CONF.baremetal.base_dir_path, image_info['image_ref'][0])

    if missing_labels:
        raise exception.NovaException(_(
            "Can not activate PXE bootloader. The following boot parameters "
            "were not passed to baremetal driver: %s") % missing_labels)
    return image_info


class PXE(base.NodeDriver):
    """PXE bare metal driver."""

    def __init__(self, virtapi):
        super(PXE, self).__init__(virtapi)
        self.os_install_manager = importutils.import_object(
            CONF.baremetal.os_install_manager)

    def _cache_tftp_images(self, context, instance, image_info):
        """Fetch the necessary kernels and ramdisks for the instance."""
        fileutils.ensure_tree(CONF.baremetal.base_dir_path)

        LOG.debug(_("Fetching kernel and ramdisk for instance %s") %
                  instance['name'])
        for label in image_info.keys():
            (uuid, path) = image_info[label]
            if not os.path.isfile(path):
                bm_utils.cache_image(
                    context=context,
                    target=path,
                    image_id=uuid,
                    user_id=instance['user_id'],
                    project_id=instance['project_id'],
                )
            bm_utils.create_link_without_raise(
                path,
                os.path.join(CONF.baremetal.tftp_root,
                             instance['uuid'], label))

    def _cache_image(self, context, instance, image_meta):
        """Fetch the instance's image from Glance

        This method pulls the relevant AMI from Glance, and writes them to
        the appropriate places on local disk.
        """
        fileutils.ensure_tree(get_image_dir_path(instance))
        image_path = get_image_file_path(instance)

        LOG.debug(_("Fetching image %(ami)s for instance %(name)s") %
                  {'ami': image_meta['id'], 'name': instance['name']})
        bm_utils.cache_image(context=context,
                             target=image_path,
                             image_id=image_meta['id'],
                             user_id=instance['user_id'],
                             project_id=instance['project_id'])

        return [image_meta['id'], image_path]

    def cache_images(self, context, node, instance,
                     admin_password, image_meta, injected_files, network_info):
        """Dodai Baremetal Driver does retrieve just a one image from
        Glance.
        """
        instance_type = self.virtapi.instance_type_get(
            context, instance['instance_type_id'])
        fileutils.ensure_tree(
            os.path.join(CONF.baremetal.tftp_root, instance['uuid']))
        tftp_image_info = get_tftp_image_info(instance, instance_type)
        self._cache_tftp_images(context, instance, tftp_image_info)
        self._cache_image(context, instance, image_meta)

    def destroy_images(self, context, node, instance):
        """Delete instance's image file."""
        bm_utils.unlink_without_raise(get_image_file_path(instance))
        bm_utils.rmtree_without_raise(get_image_dir_path(instance))

    def activate_bootloader(self, context, node, instance):
        instance_type = self.virtapi.instance_type_get(
            context, instance['instance_type_id'])
        (root_mb, swap_mb, ephemeral_mb, kdump_mb) = \
            get_partition_sizes(instance, instance_type)
        pxe_config_file_path = get_pxe_config_file_path(instance)
        image_file_path = get_image_file_path(instance)
        deployment_key = bm_utils.random_alnum(32)
        db.bm_node_update(context, node['id'],
                          {'deploy_key': deployment_key,
                           'image_path': image_file_path,
                           'pxe_config_path': pxe_config_file_path,
                           'root_mb': root_mb,
                           'swap_mb': swap_mb})
        os_install_url = self.os_install_manager.prep_os_install_manager(
            instance['image_ref'], node['prov_ip_address'])
        image_info = get_tftp_image_info(instance, instance_type)
        root_fs_type = \
            get_root_fs_type(instance, image_info['image_ref'][1])
        pxe_config = build_pxe_config(
            os.path.join(CONF.baremetal.tftp_root,
                         instance['uuid'], "deploy_kernel"),
            os.path.join(CONF.baremetal.tftp_root,
                         instance['uuid'], "deploy_ramdisk"),
            root_mb,
            swap_mb,
            ephemeral_mb,
            kdump_mb,
            os_install_url,
            node['prov_ip_address'],
            node['prov_mac_address'],
            node['host_name'],
            root_fs_type,
        )
        bm_utils.write_to_file(pxe_config_file_path, pxe_config)

        mac_path = get_pxe_mac_path(node['prov_mac_address'])
        bm_utils.unlink_without_raise(mac_path)
        bm_utils.create_link_without_raise(pxe_config_file_path, mac_path)

    def activate_bootloader_for_delete(self, context, node, instance):
        instance_type = self.virtapi.instance_type_get(
            context, instance['instance_type_id'])
        (root_mb, swap_mb, ephemeral_mb, kdump_mb) = \
            get_partition_sizes(instance, instance_type)
        pxe_config_file_path = get_pxe_config_file_path(instance)
        os_install_url = self.os_install_manager.prep_os_install_manager(
            instance['image_ref'], node['prov_ip_address'])
        image_info = get_tftp_image_info(instance, instance_type)
        root_fs_type = \
            get_root_fs_type(instance, image_info['image_ref'][1])
        pxe_config = build_pxe_config(
            os.path.join(CONF.baremetal.tftp_root,
                         instance['uuid'], "deploy_kernel"),
            os.path.join(CONF.baremetal.tftp_root,
                         instance['uuid'], "deploy_ramdisk"),
            root_mb,
            swap_mb,
            ephemeral_mb,
            kdump_mb,
            os_install_url,
            node['prov_ip_address'],
            node['prov_mac_address'],
            node['host_name'],
            root_fs_type,
            is_delete=True
        )
        bm_utils.write_to_file(pxe_config_file_path, pxe_config)

        mac_path = get_pxe_mac_path(node['prov_mac_address'])
        bm_utils.unlink_without_raise(mac_path)
        bm_utils.create_link_without_raise(pxe_config_file_path, mac_path)

    def deactivate_bootloader(self, context, node, instance):
        """Delete PXE bootloader images and config."""
        try:
            db.bm_node_update(context, node['id'],
                              {'deploy_key': None,
                              'image_path': None,
                              'pxe_config_path': None,
                              'root_mb': 0,
                              'swap_mb': 0})
        except exception.NodeNotFound:
            pass

        # NOTE(danms): the instance_type extra_specs do not need to be
        # present/correct at deactivate time, so pass something empty
        # to avoid an extra lookup
        instance_type = dict(extra_specs={
            'baremetal:deploy_ramdisk_id': 'ignore',
            'baremetal:deploy_kernel_id': 'ignore'})
        try:
            image_info = get_tftp_image_info(instance, instance_type)
        except exception.NovaException:
            pass
        else:
            for label in image_info.keys():
                (uuid, path) = image_info[label]
                bm_utils.unlink_without_raise(path)

        bm_utils.unlink_without_raise(get_pxe_config_file_path(instance))
        bm_utils.unlink_without_raise(get_pxe_mac_path(
            node['prov_mac_address']))

        bm_utils.rmtree_without_raise(
            os.path.join(CONF.baremetal.tftp_root, instance['uuid']))
        self.os_install_manager.post_os_install_manager(
            instance['image_ref'], node['prov_ip_address'])

    def activate_node(self, context, node, instance):
        """Wait for PXE deployment to complete."""

        locals = {'error': '', 'started': False}
        pxe_deploy_timeout = CONF.baremetal.pxe_deploy_timeout
        pxe_deploy_check_timeout = CONF.baremetal.pxe_deploy_check_timeout
        pxe_deploy_check_interval = CONF.baremetal.pxe_deploy_check_interval
        machine_state = "deploying"

        def _get_for_deploy_rest():
            target_ip = node['prov_ip_address']
            target_port = CONF.baremetal.dodai_instance_agent_bind_port
            path = "http://%s:%d/services/dodai-instance/state.json" %\
                   (target_ip, target_port)
            http = httplib2.Http()
            try:
                resp, body = http.request(path, 'GET')
                if resp.status >= 400:
                    locals['error'] = _("Get deployed status "
                                        "from the physical machine")
                    raise exception.InstanceDeployFailure(
                        locals['error'] % instance['uuid'])
                return body
            except Exception as e:
                LOG.debug(_("state.json error: %s") % str(e))
                return None

        def _replace_boot_config():
            """Replace boot config"""
            LOG.debug(_("replace boot config"))
            pxe_config_file_path = get_pxe_config_file_path(instance)
            tmpfd, tmpname = tempfile.mkstemp(dir=CONF.baremetal.tftp_root)
            write_file = os.fdopen(tmpfd, 'w')
            read_file = open(pxe_config_file_path)
            try:
                for line in read_file:
                    line = line.rstrip()
                    if line.find("default deploy") != -1:
                        line = "default boot"
                    line = line + "\n"
                    write_file.write(line)
            finally:
                read_file.close()
            write_file.close()
            shutil.copyfile(tmpname, pxe_config_file_path)
            os.remove(tmpname)

        def _wait_for_deploy():
            """Called at an interval until the deployment completes."""
            state = _get_for_deploy_rest()
            LOG.debug(_("state: %s") % state)
            try:
                if state is None:
                    LOG.info(_("wait until the PC to start for instance %s") %
                             instance['uuid'])
                elif state.find(baremetal_states.DEPLOYING) != -1:
                    LOG.info(_("wait to state json file for instance %s") %
                             instance['uuid'])
                    locals['started'] = True
                elif state.find(baremetal_states.DEPLOYDONE) != -1 or \
                        state.find(baremetal_states.ACTIVE) != -1:
                    LOG.info(_("PXE deploy completed for instance %s") %
                             instance['uuid'])
                    _replace_boot_config()
                    raise utils.LoopingCallDone()
                elif state.find(baremetal_states.DEPLOYFAIL) != -1:
                    locals['error'] = _("PXE deploy failed for instance %s")
            except exception.NodeNotFound:
                locals['error'] = _("Baremetal node deleted while waiting "
                                    "for deployment of instance %s")

            if (CONF.baremetal.pxe_deploy_timeout and
                    timeutils.utcnow() > expiration):
                locals['error'] = _("Timeout reached while waiting for "
                                    "PXE deploy of instance %s")
            if locals['error']:
                raise utils.LoopingCallDone()

        expiration = timeutils.utcnow() + datetime.timedelta(
            seconds=pxe_deploy_timeout)
        timer = utils.FixedIntervalLoopingCall(_wait_for_deploy)
        timer.start(interval=pxe_deploy_check_interval).wait()

        if locals['error']:
            raise exception.InstanceDeployFailure(
                locals['error'] % instance['uuid'])

    def deactivate_node(self, context, node, instance):
        pass

    def deactivate_node_for_delete(self, context, node, instance):
        """Wait for PXE delete to complete."""

        locals = {'error': '', 'started': False}
        pxe_delete_timeout = CONF.baremetal.pxe_deploy_timeout
        pxe_delete_check_timeout = CONF.baremetal.pxe_deploy_check_timeout
        pxe_delete_check_interval = CONF.baremetal.pxe_deploy_check_interval
        machine_state = "deleting"

        def _get_for_delete_rest():
            target_ip = node['prov_ip_address']
            target_port = CONF.baremetal.dodai_instance_agent_bind_port
            path = "http://%s:%d/services/dodai-instance/state.json" %\
                   (target_ip, target_port)
            http = httplib2.Http()
            try:
                resp, body = http.request(path, 'GET')
                if resp.status >= 400:
                    locals['error'] = _("Get deleted status "
                                        "from the physical machine")
                    raise exception.InstanceDeployFailure(
                        locals['error'] % instance['uuid'])
                return body
            except Exception as e:
                LOG.debug(_("state.json error: %s") % str(e))
                return None

        def _wait_for_delete():
            """Called at an interval until the delete completes."""
            state = _get_for_delete_rest()
            LOG.debug(_("state: %s") % state)
            try:
                if state is None:
                    LOG.info(_("wait until the PC to start for instance %s") %
                             instance['uuid'])
                elif state.find(baremetal_states.DELETING) != -1:
                    LOG.info(_("wait to state json file for instance %s") %
                             instance['uuid'])
                    locals['started'] = True
                elif state.find(baremetal_states.DELETEDONE) != -1 or \
                        state.find(baremetal_states.DELETED) != -1:
                    LOG.info(_("PXE delete completed for instance %s") %
                             instance['uuid'])
                    raise utils.LoopingCallDone()
                elif state.find(baremetal_states.DELETEFAIL) != -1:
                    locals['error'] = _("PXE delete failed for instance %s")
            except exception.NodeNotFound:
                locals['error'] = _("Baremetal node deleted while waiting "
                                    "for delete	 of instance %s")

            if (CONF.baremetal.pxe_deploy_timeout and
                    timeutils.utcnow() > expiration):
                locals['error'] = _("Timeout reached while waiting for "
                                    "PXE delete of instance %s")
            if locals['error']:
                raise utils.LoopingCallDone()

        expiration = timeutils.utcnow() + datetime.timedelta(
            seconds=pxe_delete_timeout)
        timer = utils.FixedIntervalLoopingCall(_wait_for_delete)
        timer.start(interval=pxe_delete_check_interval).wait()

        if locals['error']:
            raise exception.InstanceDeployFailure(
                locals['error'] % instance['uuid'])
