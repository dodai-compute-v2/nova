#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015 National Institute of Informatics.
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
Shellinabox proxy.
"""

import os
import logging
import time
import threading

from oslo.config import cfg

from nova import config
from nova.consoleauth import rpcapi as consoleauth_rpcapi
from nova import context

opts = [
    cfg.StrOpt('nginxproxy_host',
               default='0.0.0.0',
               help='IP address of Nginx proxy server'),
    cfg.IntOpt('nginxproxy_port',
               default=8084,
               help='Port number of Nginx proxy server'),
    cfg.StrOpt('nginxproxy_confdir',
               default='/etc/nginx/shellinaboxproxy.d/',
               help='Directory path for storing proxy config file'),
    cfg.IntOpt('nginxproxy_gc_interval',
               default=660,
               help='GC execution interval for proxy config file'),
    ]
CONF = cfg.CONF
CONF.register_cli_opts(opts)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(process)d] [%(levelname)s] %(message)s"
)

class Revoker(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        config.parse_args([])
        ctxt = context.get_admin_context()
        rpcapi = consoleauth_rpcapi.ConsoleAuthAPI()
        while True:
            files = os.listdir(CONF.nginxproxy_confdir)
            deleted = False
            for conf_file in files:
                token, ext = os.path.splitext(conf_file)
                if not rpcapi.check_token(ctxt, token=token):
                    logging.info("Revoker: token %s is expired" % token)
                    os.remove("%s%s.conf" % (CONF.nginxproxy_confdir, token))
                    deleted = True
            if deleted:
                logging.info("Revoker: nginx reload")
                os.system('/usr/sbin/service nginx reload')
            time.sleep(CONF.nginxproxy_gc_interval)


def get_token(environ):
    query = environ.get('QUERY_STRING', None)
    if query is not None and 'token' in query:
        token = query.split('token=', 1)[1].split('&', 1)[0]
        return token
    return None

def server(environ, start_response):
    config.parse_args([])
    token = get_token(environ)
    ctxt = context.get_admin_context()
    rpcapi = consoleauth_rpcapi.ConsoleAuthAPI()
    connect_info = rpcapi.check_token(ctxt, token=token)
    if not connect_info:
        logging.error("Invalid Token: %s", token)
        raise Exception("Invalid Token")
    host = connect_info['host']
    port = int(connect_info['port'])
    proxy_pass = "http://%s:%s/" % (host, port)
    proxy_conf = "%s%s.conf" % (CONF.nginxproxy_confdir, token)
    logging.info("will create %s" % proxy_conf)
    with open(proxy_conf, 'w') as f:
        f.write("location /%s/ {\n"
                "    proxy_pass %s;\n"
                "}" % (token, proxy_pass))

    logging.info("nginx reload")
    result = os.system('/usr/sbin/service nginx reload')
    time.sleep(1)
    if 0 is result:
        code = "307 Temporary Redirect"
        url = ("http://%s:%s/%s/" %
              (CONF.nginxproxy_host, CONF.nginxproxy_port, token))
        start_response(code, [
            ("Location", url)
        ])
        return iter(["Rendering physical machine console..."])
    else:
        raise Exception("Cannot reload nginx")

revoker = Revoker()
revoker.start()
