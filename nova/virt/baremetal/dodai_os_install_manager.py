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

import datetime
import os
import re
import sys
import tempfile
import shutil
import commands
import socket

from oslo.config import cfg

from nova import exception
from nova.openstack.common.db import exception as db_exc
from nova.openstack.common import fileutils
from nova.openstack.common import log as logging
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
        return self._launch_rsyncd(image_id, prov_ip_address)

    def post_os_install_manager(self, image_id, prov_ip_address):
        """Wrapper function for calling the _kill_rsyncd()"""
        self._kill_rsyncd(image_id, prov_ip_address)

    def _launch_rsyncd(self, image_id, allow_host):
        """Start the rsyncd"""
        if not os.path.isdir(CONF.baremetal.rsync_conf_path):
            fileutils.ensure_tree(CONF.baremetal.rsync_conf_path)
        if not os.path.isdir(CONF.baremetal.rsync_pid_path):
            fileutils.ensure_tree(CONF.baremetal.rsync_pid_path)

        rsync_config_file_path = get_rsync_config_file_path(image_id)

        if not os.path.isfile(rsync_config_file_path):
            "get glance image"
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
            self._add_allow_host(image_id, allow_host)
            tcp_port = self._get_tcp_port_by_image_id(image_id)
            base_image_file_path = get_base_image_file_path(image_id)

        rsync_url = "rsync://" + CONF.baremetal.rsync_ip + ":" + \
                    str(tcp_port) + "/" + image_id
        LOG.debug(_("launch_rsync complete"))
        return rsync_url

    def _kill_rsyncd(self, image_id, allow_host):
        """Stop the rsyncd"""
        LOG.debug(_("launch_kill_rsync"))
        rsync_config_file_path = get_rsync_config_file_path(image_id)

        for host_ip in self._list_allow_host(image_id):
            if str(allow_host) != str(host_ip):
                self._remove_allow_host(image_id, allow_host)
                LOG.debug(_("launch_kill_rsync complete"))
                return
        self._remove_allow_host(image_id, allow_host)
        rsync_pid_file_path = get_rsync_pid_file_path(image_id)
        read_file = open(rsync_pid_file_path, 'r')
        for line in read_file:
            pid = int(line.rstrip())
        utils.execute('kill', '-9', pid, run_as_root=True)
        rsync_config_file_path = get_rsync_config_file_path(image_id)
        if os.path.isfile(rsync_config_file_path):
            os.remove(rsync_config_file_path)
        if os.path.isfile(rsync_pid_file_path):
            os.remove(rsync_pid_file_path)
        utils.execute('umount', get_base_image_file_path(image_id),
                      run_as_root=True)
        LOG.debug(_("launch_kill_rsync complete"))

    def _add_allow_host(self, image_id, allow_host):
        """Add a allow_host to rsyncd configuration of the machine image"""
        rsync_config_file_path = get_rsync_config_file_path(image_id)

        tmpfd, tmpname = tempfile.mkstemp(dir=CONF.baremetal.rsync_conf_path)
        write_file = os.fdopen(tmpfd, 'w')
        read_file = open(rsync_config_file_path)
        try:
            for line in read_file:
                line = line.rstrip()
                if line.find(self.config_allow) != -1:
                    if line.find(allow_host) == -1:
                        line = ",".join([line, str(allow_host)])
                        allow_host = None
                line = line + "\n"
                write_file.write(line)
        except exception.NovaException:
            pass
        finally:
            read_file.close()
            write_file.close()
        shutil.copyfile(tmpname, rsync_config_file_path)
        os.remove(tmpname)

    def _list_allow_host(self, image_id):
        """Returns a list of hosts from rsyncd settings of the machine image"""
        rsync_config_file_path = get_rsync_config_file_path(image_id)

        read_file = open(rsync_config_file_path, 'r')
        try:
            for line in read_file:
                line = line.rstrip()
                if line.find(self.config_allow) != -1:
                    line = line[line.find('=') + 2:]
                    host_list = line.split(',')
        except exception.NovaException:
            pass
        finally:
            read_file.close()

        return host_list

    def _remove_allow_host(self, image_id, allow_host):
        """From rsyncd settings of the machine image, remove the allow_host
        specified
        """
        rsync_config_file_path = get_rsync_config_file_path(image_id)

        tmpfd, tmpname = tempfile.mkstemp(dir=CONF.baremetal.rsync_conf_path)
        write_file = os.fdopen(tmpfd, 'w')
        read_file = open(rsync_config_file_path)
        try:
            for line in read_file:
                line = line.rstrip()
                if line.find(self.config_allow) != -1:
                    line = line[line.find('=') + 2:]
                    line_el = line.split(',')
                    line_el.remove(allow_host)
                    if len(line_el) == 0:
                        continue
                    else:
                        line = "hosts allow = " + ','.join(line_el)
                line = line + "\n"
                write_file.write(line)
        except exception.NovaException:
            pass
        finally:
            read_file.close()
            write_file.close()

        shutil.copyfile(tmpname, rsync_config_file_path)
        os.remove(tmpname)

    def _get_tcp_port_by_image_id(self, image_id):
        """Return the port number that is using the machine image"""
        return commands.getoutput("ps aux | grep " + image_id +
                                  " | grep -v grep | awk '{print $16}'")

    def _get_available_port(self):
        sock = socket.socket()
        sock.bind(("localhost", 0))
        port_number = sock.getsockname()[1]
        sock.close()
        return port_number
