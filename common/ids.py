from common.utils import ssh_connect, ssh_command

def restart_ids(vm):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, 'sudo service ids restart')
