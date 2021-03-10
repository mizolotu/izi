import vagrant, json
import argparse as arp

from common.utils import find_vms, find_mgmt_ip, find_vm_ips

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Create VMs')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-t', '--tunnels', help='File with tunnels', default='logs/tunnels.json')
    args = parser.parse_args()

    # start vagrant

    v = vagrant.Vagrant()
    v.up(provision=True)

    # find vms and ips

    vms = find_vms()
    ips = find_vm_ips(vms)
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

    # save vms with ips and keys

    vms_ips = []
    for vm, ip, mgmt_ip, key in zip(vms, ips, mgmt_ips, keyfiles):
        vms_ips.append({'vm': vm, 'ip': ip, 'mgmt': mgmt_ip, 'key': key})
    with open(args.vms, 'w') as f:
        json.dump(vms_ips, f)

