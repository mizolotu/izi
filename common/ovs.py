from common.utils import ssh_connect, ssh_command

def connect_to_controller(vm, br, ctrl_ip, ctrl_port):
    keyfile = vm['key']
    mgmt = vm['mgmt']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, f'sudo ovs-vsctl set-controller {br} tcp:{ctrl_ip}:{ctrl_port}')

def create_veth_pair(vm, br, other):
    keyfile = vm['key']
    mgmt = vm['mgmt']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, f'sudo ip link add {br}_{other} type veth peer name {other}_{br}')
    ssh_command(ssh, f'sudo ovs-vsctl add-port {br} {br}_{other}')
    ssh_command(ssh, f'sudo ip link set dev {other}_{br} up')
    ssh_command(ssh, f'sudo ip link set dev {br}_{other} up')
    ofport = get_iface_ofport(ssh, f'{br}_{other}')
    return ofport

def delete_veth_pair(vm, br, other):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, f'sudo ip link del {br}_{other} type veth peer name {other}_{br}')

def add_default_tgu_flow(vm, idx, br='br'):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, 'sudo ovs-ofctl add-flow {0} \"table=0,in_port=out{1},action=output:t_s_{1}\"'.format(br, idx))

def add_sflow_agent(vm, collector_ip):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, f'sudo ovs-vsctl -- --id=@sflow create sflow agent=eth1 target="\\\"{collector_ip}:6343\"\\" header=128 polling=1 sampling=1 -- set bridge br sflow=@sflow')

def create_vxlan_tunnel(vm, vxlan, ip, br='br'):
    mgmt = vm['mgmt']
    keyfile = vm['key']
    ssh = ssh_connect(mgmt, keyfile)
    #cmd = 'sudo ovs-vsctl add-port {0} {1} -- set interface {1} type=vxlan options:remote_ip={2}'.format(br, vxlan, ip, br)
    cmd = 'sudo ovs-vsctl add-port {0} {1} -- set interface {1} type=gre options:remote_ip={2}'.format(br, vxlan, ip, br)
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
    lines = ssh_command(ssh, 'sudo ovs-ofctl del-flows br')
    for line in lines:
        print(line)

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