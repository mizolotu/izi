import json

from common.utils import ssh_copy, ssh_restart_service
from config import *

if __name__ == '__main__':

    # load vms

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    # retrieve ovs and ids vms

    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs']
    ids_vms = [vm for vm in vms if vm['role'] == 'ids']

    # copy ids files and restart service

    for vm in ids_vms:
        ssh_copy(vm, ids_sources_dir, ids_remote_dir)
        ssh_restart_service(vm, 'ids')

    # copy ids files and restart service

    for vm in ovs_vms:
        ssh_copy(vm, ovs_sources_dir, ovs_remote_dir)
        ssh_restart_service(vm, 'ovs')