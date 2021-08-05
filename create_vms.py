import vagrant, json
import argparse as arp

from common.utils import find_vms, find_mgmt_ip, find_vm_ips, clean_dir
from config import *

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Create VMs.')
    parser.add_argument('-p', '--provision', help='Provision?', default=False, type=bool)
    args = parser.parse_args()

    # start vagrant

    v = vagrant.Vagrant()
    v.up(provision=args.provision)

    # find vms and ips

    vms = find_vms()
    control_ips, data_ips = find_vm_ips(vms)
    mgmt_ips = []
    for vm in vms:
        mgmt_ip = find_mgmt_ip(v, vm)
        mgmt_ips.append(mgmt_ip)

    # extract key files for faster ssh access

    keyfiles = []
    fpath='.vagrant/machines/{0}/libvirt/private_key'
    for vm in vms:
        keyfile = fpath.format(vm)
        keyfiles.append(keyfile)

    # clean old logs

    clean_dir(log_dir, postfix='.json')

    # assign roles

    roles = []
    for vm in vms:
        if vm.startswith('ids'):
            roles.append('ids')
        elif vm.startswith('ovs'):
            roles.append('ovs')
        elif vm.startswith(ctrl_name):
            roles.append('sdn')
        else:
            roles.append('other')

    # save vms with ips and keys

    vms_with_ips = []
    for vm, ip, data_ip, mgmt_ip, key, role in zip(vms, control_ips, data_ips, mgmt_ips, keyfiles, roles):
        vms_with_ips.append({'vm': vm, 'ip': ip, 'mgmt': mgmt_ip, 'data': data_ip, 'key': key, 'role': role})
    with open(vms_fpath, 'w') as f:
        json.dump(vms_with_ips, f)