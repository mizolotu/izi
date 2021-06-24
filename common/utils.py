import paramiko, requests, os
import os.path as osp

from time import sleep

def vagrantfile_provider(mgmt_network='192.168.122.0/24', storage_pool_name=None):
    lines = []
    lines.append("ENV['VAGRANT_DEFAULT_PROVIDER'] = 'libvirt'\n")
    lines.append("Vagrant.configure('2') do | config |\n\n")
    lines.append("  config.vm.provider :libvirt do |libvirt|\n")
    if storage_pool_name is not None:
        lines.append(f"    libvirt.storage_pool_name = '{storage_pool_name}'\n")
    lines.append("    libvirt.management_network_name = 'default'\n")
    lines.append(f"    libvirt.management_network_address = '{mgmt_network}'\n")
    lines.append("  end\n\n")
    return lines

def vagrantfile_vms(names, cpus, ips, sources, scripts, mounts, ubuntu):
    assert len(names) == len(cpus)
    assert len(names) == len(ips)
    assert len(names) == len(scripts)
    assert len(names) == len(mounts)
    lines = []
    for name, ncpus, ip_list, source_list, script, mount in zip(names, cpus, ips, sources, scripts, mounts):
        lines.append(f"  config.vm.define '{name}', primary: true do |{name}|\n")
        lines.append(f"    {name}.vm.box = 'generic/ubuntu{ubuntu}'\n")
        lines.append(f"    {name}.vm.provider :libvirt do |v|\n")
        lines.append(f"      v.cpus = {ncpus}\n")
        lines.append("    end\n")
        for ip in ip_list:
            lines.append(f"    {name}.vm.network :private_network, :ip => '{ip}'\n")
        for source in source_list:
            lines.append(f"    {name}.vm.provision 'file', source: '{source[0]}', destination: '{source[1]}'\n")
        if mount is not None:
            lines.append(f"    {name}.vm.synced_folder '{mount[0]}', '{mount[1]}', type: 'nfs', nfs_udp: false\n")
        lines.append(f"    {name}.vm.provision :shell, :path => '{script}', privileged: false\n")
        lines.append("  end\n\n")
    return lines

def vagrantfile_end():
    return ['end']

def increment_ips(ips):
    new_ips = []
    for ip in ips:
        spl = ip.split('.')
        spl[-1] = str(int(spl[-1]) + 1)
        new_ips.append('.'.join(spl))
    return new_ips

def find_vms(fname='Vagrantfile'):
    vms = []
    with open(fname, 'r') as vf:
        lines = vf.readlines()
    for line in lines:
        if 'config.vm.define' in line:
            vm = line.split('|')[1]
            vms.append(vm)
    return vms

def find_vm_ips(vms, fname='Vagrantfile'):
    control_ips = []
    data_ips = []
    with open(fname, 'r') as vf:
        lines = vf.readlines()
    for vm in vms:
        control_ip = None
        data_ip = None
        for line in lines:
            if '{0}.vm.network :private_network, :ip'.format(vm) in line:
                spl = line.strip().split(' ')
                ip = spl[-1][1:-1]
                if control_ip is None:
                    control_ip = ip
                elif data_ip is None:
                    data_ip = ip
                else:
                    break
        control_ips.append(control_ip)
        data_ips.append(data_ip)
    return control_ips, data_ips

def find_mgmt_ip(v, vm):
    ip = ''
    lines = v.ssh_config(vm).split('\n')
    for line in lines:
        if 'HostName ' in line:
            ip = line.split('HostName ')[1]
            break
    return ip

def gateway(ip):
    spl = ip.split('.')
    spl[-1] = '1'
    return '.'.join(spl)

def network(ip):
    spl = ip.split('.')
    spl[-1] = '0'
    return '.'.join(spl)

def mac_hex(ip, prefix="00:00"):
    mac_str = '{0}:{1}'.format(prefix, ':'.join(['%02x' % (int(octet)) for octet in ip.split('.')]))
    mac_hex = '0x' + ''.join(mac_str.split(':'))
    return mac_str, mac_hex

def ip_hex(ip):
    return ip, '0x{:02X}{:02X}{:02X}{:02X}'.format(*map(int, ip.split('.')))

def ssh_connect(ip, keyfile, user='vagrant'):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key = paramiko.RSAKey.from_private_key_file(keyfile)
    ssh.connect(ip, username=user, pkey=key)
    return ssh

def ssh_command(ssh, command, sleeptime=0.001):
    stdin, stdout, stderr = ssh.exec_command(command)
    while not stdout.channel.exit_status_ready():
        sleep(sleeptime)
    return stdout.readlines()

def ssh_copy(vm, source_dir, destination_dir):
    keyfile = vm['key']
    mgmt = vm['mgmt']
    ssh = ssh_connect(mgmt, keyfile)
    ftp_client = ssh.open_sftp()
    for root, dirs, files in os.walk(source_dir, topdown=False):
        for name in files:
            source = osp.join(root, name)
            destination = source.replace(source_dir, destination_dir)
            ftp_client.put(source, destination)
    ftp_client.close()
    ssh.close()

def ssh_restart_service(vm, service):
    keyfile = vm['key']
    mgmt = vm['mgmt']
    ssh = ssh_connect(mgmt, keyfile)
    ssh_command(ssh, f'sudo service {service} restart')

def nat_ip(ip, prefix):
    pspl = prefix.split('.')
    l = len(pspl)
    ispl = ip.split('.')
    spl = pspl + ispl[l:]
    return '.'.join(spl)

def ip_proto(value):
    if isint(value):
        proto_number = int(value)
        if proto_number == 1:
            proto = 'icmp'
        elif proto_number == 6:
            proto = 'tcp'
        elif proto_number == 17:
            proto = 'udp'
        else:
            print(value)
            raise NotImplemented
    else:
        proto = value
        if proto == 'icmp':
            proto_number = 1
        elif proto == 'tcp':
            proto_number = 6
        elif proto == 'udp':
            proto_number = 17
        else:
            print(value)
            raise NotImplemented
    return proto, proto_number

def isint(value):
    try:
        int(value)
        result = True
    except:
        result = False
    return result

def parse_fname_ip(fname, prefix='172.31.69.'):
    spl = fname.split(prefix)
    n = 0
    for i, c in enumerate(spl[1]):
        if isint(c):
            n += 1
        else:
            break
    x = spl[1][:n]
    if len(x) > 0:
        result = '{0}{1}'.format(prefix, x)
    else:
        result = None
    return result

def download_controller(dir='sources', version='0.12.3', source='https://nexus.opendaylight.org/content/repositories/opendaylight.release/org/opendaylight/integration/opendaylight'):
    fname = 'opendaylight-{0}.tar.gz'.format(version)
    fpath = osp.join(dir, fname)
    url = '{0}/{1}/{2}'.format(source, version, fname)
    if not osp.isfile(fpath):
        r = requests.get(url, allow_redirects=True)
        open(fpath, 'wb').write(r.content)

def clean_dir(dir_name, postfix):
    for f in os.listdir(dir_name):
        if osp.isfile(osp.join(dir_name, f)) and f.endswith(postfix):
            os.remove(osp.join(dir_name, f))







