#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Kevin Breit (@kbreit) <kevin.breit@kevinbreit.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = r'''
---
module: meraki_mx_port_forward
short_description: Manage port forwarding rules on the mx appliance in the Meraki cloud
version_added: "2.7"
description:
- Allows for creation, management, and visibility into port forwarding rules implemented on Meraki MX firewalls.
notes:
- Module assumes a complete list of port forwarding rules are passed as a parameter.
- If there is interest in this module allowing manipulation of a single port forwarding rule, please submit an issue against this module.
options:
    state:
        description:
        - Create or query the port forwarding list.
        choices: ['present', 'query']
        default: present
    org_name:
        description:
        - Name of organization.
        - If C(clone) is specified, C(org_name) is the name of the new organization.
    org_id:
        description:
        - ID of organization.
    net_name:
        description:
        - Name of network which MX firewall is in.
    net_id:
        description:
        - ID of network which MX firewall is in.
    rules:
        description:
        - List of port forwarding rules.
        suboptions:
            name:
                description:
                - short name for the rule
            lan_ip:
                description:
                - Lan IP address
            uplink:
                description:
                - Uplink interface
                Choices: ['internet1', 'internet2', 'both']
            public_port
                description:
                - Comma seperated list of public port nummbers that will be forward to the LAN host
            local_port:
                description:
                - Comma seperated list of port numbers that will receive the forwarded traffic
            allowed_ips:
                description:
                - Comma separated list of public ip addresses that are allowed to make an inbound connection on the specified ports.
            protocol:
                description:
                - Protocol for the connection
                Choices: ['TCP', 'UDP']
author:
- Bryan Thompson (@conundrum2k)
- based on meraki_mx_l3_firewall module by Kevin Breit
- Kevin Breit (@kbreit)
extends_documentation_fragment: meraki
'''

EXAMPLES = r'''
- name: Query port forwarding rules
  meraki_mx_port_forward:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: query
  delegate_to: localhost

- name: Set two port forwarding rules
  meraki_mx_port_forward:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    rules:
      - name: Forward web traffic
        lan_ip: 192.0.1.50
        uplink: both
        public_port: 80
        local_port: 80
        allowed_ips: 
          - 1.1.1.1
          - 2.2.2.2
        protocol: tcp
      - name: Forward ssh traffic
        lan_ip: 192.0.1.51
        uplink: Internet1
        public_port: 22
        local_port: 22
        allowd_ips:
          - 1.1.1.1
        protocol: tcp
  delegate_to: localhost

- name: Set one port forwarding rule
  meraki_mx_port_forward:
    auth_key: abc123
    org_name: YourOrg
    net_name: YourNet
    state: present
    rules:
      - name: allow BO
        lan_ip: 192.168.1.65
        uplink: both
        public_port: 31337
        local_port: 31337
        allowd_ips:
          - any
        protocol: any
  delegate_to: localhost
'''

RETURN = r'''
data:
    description: Port forwarding rules associated to network.
    returned: success
    type: complex
    contains:
        name:
            description: A descritive name for the rule
            returned: always
            type: str
            sample: webserver
        lan_ip:
            description: IP of the server or device that hosts the internal resource
            returned: always
            type: str
            sample: 192.168.1.2
        uplink:
            description: Physical WAN interface on which the traffic will arrive
            returned: always
            type: str
            sample: both
        public_port:
            description: port or port range forwarded to the host on the LAN
            returned: always
            type: str
            sample: 22-443
        local_port:
            description: port or port range that will receive the forwarded traffic from the WAN
            returned: always
            type: str
            sample: 80,443
        allowd_ips:
            description: array of WAN IP address that are allowd to make connections
            returned: always
            type: str
            sample: - 8.8.8.8
        protocol:
            description: TCP or UDP
            returned: always
            type: str
            sample: tcp
'''

import os
from ansible.module_utils.basic import AnsibleModule, json, env_fallback
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_native
from ansible.module_utils.network.meraki.meraki import MerakiModule, meraki_argument_spec


def assemble_payload(meraki):
    params_map = {'name': 'name',
                  'lan_ip': 'lanIp',
                  'uplink': 'uplink',
                  'public_port': 'publicPort',
                  'local_port': 'localPort',
                  'allowed_ips': 'allowedIps',
                  'protocol': 'protocol',
                  }
    rules = []
    for rule in meraki.params['rules']:
        proposed_rule = dict()
        for k, v in rule.items():
            proposed_rule[params_map[k]] = v
        rules.append(proposed_rule)
    payload = {'rules': rules}
    return payload



def get_rules(meraki, net_id):
    path = meraki.construct_path('get_all', net_id=net_id)
    response = meraki.request(path, method='GET')
    if meraki.status == 200:
        return response


def main():
    # define the available arguments/parameters that a user can pass to
    # the module

    pf_rules = dict(name=dict(type='str'),
                    lan_ip=dict(type='str'),
                    uplink=dict(type='str', choices=['internet1', 'internet2', 'both']),
                    public_port=dict(type='str'),
                    local_port=dict(type='str'),
                    allowed_ips=dict(type='list'),
                    protocol=dict(type='str', choices=['tcp', 'udp'])
                    )                                   
                    

    argument_spec = meraki_argument_spec()
    argument_spec.update(state=dict(type='str', choices=['present', 'query'], default='present'),
                         net_name=dict(type='str'),
                         net_id=dict(type='str'),
                         rules=dict(type='list', default=None, elements='dict', options=pf_rules),
                         )

    # seed the result dict in the object
    # we primarily care about changed and state
    # change is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(
        changed=False,
    )
    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           )
    meraki = MerakiModule(module, function='mx_port_forward')

    meraki.params['follow_redirects'] = 'all'

    query_urls = {'mx_port_forward': '/networks/{net_id}/portForwardingRules/'}
    update_urls = {'mx_port_forward': '/networks/{net_id}/portForwardingRules/'}

    meraki.url_catalog['get_all'].update(query_urls)
    meraki.url_catalog['update'] = update_urls

    payload = None

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    # FIXME: Work with Meraki so they can implement a check mode
    if module.check_mode:
        meraki.exit_json(**meraki.result)

    # execute checks for argument completeness

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    org_id = meraki.params['org_id']
    orgs = None
    if org_id is None:
        orgs = meraki.get_orgs()
        for org in orgs:
            if org['name'] == meraki.params['org_name']:
                org_id = org['id']
    net_id = meraki.params['net_id']
    if net_id is None:
        if orgs is None:
            orgs = meraki.get_orgs()
        net_id = meraki.get_net_id(net_name=meraki.params['net_name'],
                                   data=meraki.get_nets(org_id=org_id))

    if meraki.params['state'] == 'query':
        meraki.result['data'] = get_rules(meraki, net_id)
    elif meraki.params['state'] == 'present':
        rules = get_rules(meraki, net_id)
        path = meraki.construct_path('get_all', net_id=net_id)
        if meraki.params['rules']:
            payload = assemble_payload(meraki)
        else:
            payload = dict()
        update = False
        try:
            if len(rules) - 1 != len(payload['rules']):  # Quick and simple check to avoid more processing
                update = True
            if update is False:
                for r in range(len(rules) - 1):
                    if meraki.is_update_required(rules[r], payload['rules'][r]) is True:
                        update = True
        except KeyError:
            pass
            # if meraki.params['syslog_default_rule']:
            #     meraki.fail_json(msg='Compare', original=rules, proposed=payload)
        if update is True:
            response = meraki.request(path, method='PUT', payload=json.dumps(payload))
            if meraki.status == 200:
                meraki.result['data'] = response
                meraki.result['changed'] = True

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    meraki.exit_json(**meraki.result)


if __name__ == '__main__':
    main()
