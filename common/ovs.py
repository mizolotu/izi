from common.utils import ssh_connect, ssh_command

def create_vxlan_tunnel(vm, vxlan, ip, br='br'):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    cmd = 'sudo ovs-vsctl add-port {0} {1} -- set interface {1} type=vxlan options:remote_ip={2}'.format(br, vxlan, ip, br)
    ssh_command(ssh, cmd)
    ofport = get_iface_ofport(ssh, vxlan)
    return ofport

def get_all_ofports(vm, br='br'):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    lines = ssh_command(ssh, 'sudo ovs-vsctl list-ifaces {0}'.format(br))
    ofports = [line.strip()[1:-1] for line in lines]
    print(ofports)
    return ofports

def get_iface_ofport(ssh, iface):
    cmd = 'sudo ovs-vsctl get interface {0} ofport'.format(iface)
    lines = ssh_command(ssh, cmd)
    assert len(lines) == 1
    return lines[0].strip()

def clean_tunnel_ports(vm, br='br'):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    cmd = 'sudo ovs-vsctl list-ifaces {0}'.format(br)
    lines = ssh_command(ssh, cmd)
    if len(lines) > 0:
        ifaces = [line.strip() for line in lines]
        for iface in ifaces:
            cmd = 'sudo ovs-vsctl get interface {0} type'.format(iface)
            lines = ssh_command(ssh, cmd)
            if len(lines) > 0:
                iface_type = lines[0].strip()
                if iface_type == 'vxlan' or iface_type == 'gre':
                    cmd = 'sudo ovs-vsctl del-port {0} {1}'.format(br, iface)
                    ssh_command(ssh, cmd)

def clean_ovs_ports(vm, br='br'):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    cmd = 'sudo ovs-vsctl list-ifaces {0}'.format(br)
    lines = ssh_command(ssh, cmd)
    if len(lines) > 0:
        ifaces = [line.strip() for line in lines]
        for iface in ifaces:
            cmd = 'sudo ovs-vsctl del-port {0} {1}'.format(br, iface)
            ssh_command(ssh, cmd)

def delete_flows(vm):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, 'sudo ovs-ofctl del-flows br')

def get_node_id(vm):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    lines = ssh_command(ssh, 'sudo ovs-vsctl get interface br mac_in_use')
    assert len(lines) == 1
    return 'openflow:{0}'.format(str(int(''.join(lines[0].strip()[1:-1].split(':')), 16)))

def set_ip(vm, ip, br='br'):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, 'sudo ip addr add {0}/24 dev {1}'.format(ip, br))
    ssh_command(ssh, 'sudo ip link set dev {0} up'.format(br))