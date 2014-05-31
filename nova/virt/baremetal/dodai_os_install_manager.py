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

"""
Class OSInstallManager for bare-metal nodes.
"""

import os
import tempfile
import shutil
import commands
import socket

from oslo.config import cfg

from nova import exception
from nova.openstack.common import fileutils
from nova.openstack.common import log as logging
from nova.openstack.common import lockutils
from nova import utils
from nova.virt.baremetal import utils as bm_utils

pxe_opts = [
    cfg.StrOpt('rsync_conf_path',
               default='/var/lib/nova/baremetal/rsync/conf/',
               help=''),
    cfg.StrOpt('rsync_pid_path',
               default='/var/lib/nova/baremetal/rsync/pid/',
               help=''),
    cfg.StrOpt('rsync_script_path',
               default='/var/lib/nova/baremetal/rsync/scripts/',
               help=''),
    cfg.StrOpt('rsync_image_path',
               default='/var/lib/nova/baremetal/rsync/images/',
               help=''),
    cfg.IntOpt('rsync_deploy_timeout',
               help='Timeout for rsync deployments. Default: 0 (unlimited)',
               default=0),
    cfg.StrOpt('rsync_config_template',
               default='$pybasedir/nova/virt/baremetal/dodai_rsync_config.'
                       'template',
               help='Template file for rsync configuration'),
    cfg.StrOpt('rsync_ip',
               help='rsync ip for rsync configuration'),
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


def build_rsync_config(pid_file, image_uuid, path, hosts_allow):
    LOG.debug(_("Building rsync config for deployment %s.") % image_uuid)
    rsync_options = {
        'pid_file': pid_file,
        'image_uuid': image_uuid,
        'path': path,
        'hosts_allow': hosts_allow,
    }
    cheetah = _get_cheetah()
    rsync_config = str(cheetah(
        open(CONF.baremetal.rsync_config_template).read(),
        searchList=[{'rsync_options': rsync_options}]))
    return rsync_config


def get_base_image_file_path(image_id):
    """Generate the path for an image file."""
    return os.path.join(CONF.baremetal.rsync_image_path, image_id)


def get_rsync_config_file_path(image_id):
    """Generate the path for an rsync config file."""
    rsync_file = image_id + ".conf"
    return os.path.join(CONF.baremetal.rsync_conf_path, rsync_file)


def get_base_file_path(image_id):
    """Generate the path for an _base directory file"""
    return os.path.join(CONF.baremetal.base_dir_path, image_id)


def get_rsync_pid_file_path(image_id):
    """Generate the path for an rsync pid file."""
    return os.path.join(CONF.baremetal.rsync_pid_path, image_id)


class DodaiOSInstallManager(object):
    """Install OS to Baremetal machine by Dodai style"""
    tcp_port_by_uuid = []
    config_allow = 'hosts allow'

    def prep_os_install_manager(self, image_id, prov_ip_address):
        """Wrapper function for calling the _launch_rsyncd()"""
        LOG.debug("prep_os_install_manager called. prov_ip_address=%s"
                  % prov_ip_address)
        return self._launch_rsyncd(image_id, prov_ip_address)

    def post_os_install_manager(self, image_id, prov_ip_address):
        """Wrapper function for calling the _kill_rsyncd()"""
        LOG.debug("post_os_install_manager called. prov_ip_address=%s"
                  % prov_ip_address)
        self._kill_rsyncd(image_id, prov_ip_address)

    @lockutils.synchronized('launch_rsyncd', 'nova-', external=True)
    def _launch_rsyncd(self, image_id, allow_host):
        """Start the rsyncd"""
        LOG.debug("_launch_rsyncd start. image_id=%s, allow_host=%s"
                  % (image_id, allow_host))
        if not os.path.isdir(CONF.baremetal.rsync_conf_path):
            fileutils.ensure_tree(CONF.baremetal.rsync_conf_path)
        if not os.path.isdir(CONF.baremetal.rsync_pid_path):
            fileutils.ensure_tree(CONF.baremetal.rsync_pid_path)

        rsync_config_file_path = get_rsync_config_file_path(image_id)

        if not os.path.isfile(rsync_config_file_path):
            "get glance image"
            LOG.debug("_launch_rsyncd: rsync_config_file %s does not exist."
                      % rsync_config_file_path)
            base_file_path = get_base_file_path(image_id)
            if not os.path.isfile(base_file_path):
                LOG.exception(_(
                    "No image of the target machine %s ") % base_file_path)
                raise BaseException
                pass

            base_image_file_path = get_base_image_file_path(image_id)
            if not os.path.isdir(CONF.baremetal.rsync_image_path):
                fileutils.ensure_tree(CONF.baremetal.rsync_image_path)
            if not os.path.isdir(base_image_file_path):
                fileutils.ensure_tree(base_image_file_path)
            utils.execute('mount', '-o', 'loop,ro', base_file_path,
                          base_image_file_path,
                          run_as_root=True)
            rsync_pid_file_path = get_rsync_pid_file_path(image_id)
            rsync_config = build_rsync_config(
                rsync_pid_file_path,
                image_id,
                base_image_file_path,
                allow_host,
            )
            bm_utils.write_to_file(rsync_config_file_path, rsync_config)
            tcp_port = self._get_available_port()
            try:
                self.tcp_port_by_uuid.append([image_id, tcp_port])
            except AttributeError:
                self.tcp_port_by_uuid = [[image_id, tcp_port]]

            utils.execute('rsync', '--daemon', '--config',
                          rsync_config_file_path, '--port',
                          str(tcp_port), run_as_root=True)
        else:
            LOG.debug("_launch_rsyncd: rsync_config_file %s exists."
                      % rsync_config_file_path)
            self._add_allow_host(image_id, allow_host)
            tcp_port = self._get_tcp_port_by_image_id(image_id)
            base_image_file_path = get_base_image_file_path(image_id)

        rsync_url = "rsync://%s:%s/%s" %\
                    (CONF.baremetal.rsync_ip, tcp_port, image_id)
        LOG.debug("_launch_rsyncd end. image_id=%s, allow_host=%s"
                  % (image_id, allow_host))
        return rsync_url

    @lockutils.synchronized('kill_rsyncd', 'nova-', external=True)
    def _kill_rsyncd(self, image_id, allow_host):
        """Stop the rsyncd"""
        LOG.debug(_("_kill_rsyncd begin"))
        rsync_config_file_path = get_rsync_config_file_path(image_id)
        if not os.path.isfile(rsync_config_file_path):
            LOG.warn(_("rsync_config_file %s not found. "
                       "so, skip _kill_rsyncd process.") %
                     rsync_config_file_path)
            return

        if allow_host in self._list_allow_host(image_id):
            self._remove_allow_host(image_id, allow_host)
        LOG.debug("_kill_rsyncd: allow_host: %s" % allow_host)
        LOG.debug("_kill_rsyncd: _list_allow_host: %s"
                  % self._list_allow_host(image_id))
        if 0 < len(self._list_allow_host(image_id)):
            LOG.debug(_("_kill_rsyncd abort"))
            return
        rsync_pid_file_path = get_rsync_pid_file_path(image_id)
        with open(rsync_pid_file_path) as rsync_pid:
            pid = rsync_pid.read().strip()
        utils.execute('kill', '-9', pid, run_as_root=True)
        if os.path.isfile(rsync_config_file_path):
            os.remove(rsync_config_file_path)
        if os.path.isfile(rsync_pid_file_path):
            os.remove(rsync_pid_file_path)
        utils.execute('umount', get_base_image_file_path(image_id),
                      run_as_root=True)
        LOG.debug(_("_kill_rsyncd complete"))

    @lockutils.synchronized('add_allow_host', 'nova-', external=True)
    def _add_allow_host(self, image_id, allow_host):
        """Add a allow_host to rsyncd configuration of the machine image"""
        LOG.debug("_add_allow_host start. image_id=%s, allow_host=%s"
                  % (image_id, allow_host))
        rsync_config_file_path = get_rsync_config_file_path(image_id)
        new_config = ''

        with open(rsync_config_file_path) as rsync_conf:
            for line in rsync_conf:
                if line.lstrip().startswith('%s = ' % self.config_allow):
                    value = self._list_allow_host(image_id)
                    if allow_host not in value:
                        LOG.debug("_add_allow_host: add %s to %s"
                                  % (allow_host, ','.join(value)))
                        new_config += ",".join([line.rstrip(),
                                                allow_host]) + "\n"
                    else:
                        LOG.debug("_add_allow_host: skip adding %s to %s"
                                  % (allow_host, ','.join(value)))
                        new_config += line
                    allow_host = None
                else:
                    new_config += line
        with open(rsync_config_file_path, 'w') as rsync_conf:
            rsync_conf.write(new_config)
        LOG.debug("_add_allow_host end. image_id=%s, allow_host=%s"
                  % (image_id, allow_host))

    def _list_allow_host(self, image_id):
        """Returns a list of hosts from rsyncd settings of the machine image"""
        rsync_config_file_path = get_rsync_config_file_path(image_id)

        with open(rsync_config_file_path) as rsync_conf:
            for line in rsync_conf:
                if line.lstrip().startswith('%s = ' % self.config_allow):
                    value = line.split('=', 1)[1].strip()
                    host_list = [] if not value else value.split(',')
                    break
                else:
                    host_list = []
        return host_list

    @lockutils.synchronized('remove_allow_host', 'nova-', external=True)
    def _remove_allow_host(self, image_id, allow_host):
        """From rsyncd settings of the machine image, remove the allow_host
        specified
        """
        LOG.debug("_remove_allow_host start. image_id=%s, allow_host=%s"
                  % (image_id, allow_host))
        rsync_config_file_path = get_rsync_config_file_path(image_id)
        new_config = ''

        with open(rsync_config_file_path) as rsync_conf:
            for line in rsync_conf:
                if line.lstrip().startswith('%s = ' % self.config_allow):
                    value = self._list_allow_host(image_id)
                    LOG.debug("_remove_allow_host: remove %s from %s"
                              % (allow_host, ','.join(value)))
                    if 0 < len(value):
                        try:
                            value.remove(allow_host)
                        except Exception as e:
                            LOG.debug(_("#DodaiOSInstallManager.\
                                _remove_allow_host(): %s" % e))
                        if 0 == len(value):
                            new_config += "hosts allow = \n"
                        else:
                            new_config += "hosts allow = " + \
                                          ','.join(value) + "\n"
                    else:
                        new_config += "hosts allow = \n"
                else:
                    new_config += line
        with open(rsync_config_file_path, 'w') as rsync_conf:
            rsync_conf.write(new_config)
        LOG.debug("_remove_allow_host end. image_id=%s, allow_host=%s"
                  % (image_id, allow_host))

    def _get_tcp_port_by_image_id(self, image_id):
        """Return the port number that is using the machine image"""
        LOG.debug("#DodaiOSInstallManager._get_tcp_port_by_image_id() called.")
        port_no = commands.getoutput("ps auxww | grep %s | grep -v grep "
                                     "| awk '{print $16}'" % image_id)
        LOG.debug("#port_no=%s" % port_no)
        try:
            port_no = int(port_no)
        except ValueError:
            reason = _("Could not get the valid port number from image id. "
                       "port_no=%s, image_id=%s") % (port_no, image_id)
            raise exception.InstanceDeployFailure(reason=reason)
        return port_no

    def _get_available_port(self):
        sock = socket.socket()
        sock.bind(("localhost", 0))
        port_number = sock.getsockname()[1]
        sock.close()
        return port_number
