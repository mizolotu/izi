import paramiko, requests, os
import os.path as osp

from time import sleep

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
    ips = []
    with open(fname, 'r') as vf:
        lines = vf.readlines()
    for vm in vms:
        for line in lines:
            if '{0}.vm.network :private_network, :ip'.format(vm) in line:
                spl = line.strip().split(' ')
                ips.append(spl[-1][1:-1])
                break
    return ips

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

def nat_ip(ip, prefix):
    pspl = prefix.split('.')
    l = len(pspl)
    ispl = ip.split('.')
    spl = pspl + ispl[l:]
    return '.'.join(spl)

def ip_ptoto(proto):
    if proto == 'icmp':
        proto_number = 1
    elif proto == 'tcp':
        proto_number = 6
    elif proto == 'udp':
        proto_number = 17
    else:
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







