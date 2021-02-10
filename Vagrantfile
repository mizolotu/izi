# -*- mode: ruby -*-
# vi: set ft=ruby :

# Use libvirt (qemu/kvm) to run virtual machine
ENV['VAGRANT_DEFAULT_PROVIDER'] = 'libvirt'

Vagrant.configure("2") do |config|

  # Define libvirt storage pool to use
  config.vm.provider :libvirt do |libvirt|
    libvirt.management_network_name = "default"
    libvirt.management_network_address = "192.168.122.0/24"
  end

  config.vm.define "odl", primary: true do |odl|
    odl.vm.box = "generic/ubuntu1804"
    odl.vm.network :private_network, :ip => "192.168.254.11"
    odl.vm.provision "file", source: "sources/opendaylight-0.12.3.tar.gz", destination: "opendaylight-0.12.3.tar.gz"
    odl.vm.provision "file", source: "sources/odl.service", destination: "/home/vagrant/"
    odl.vm.provision :shell, :path => "scripts/odl.sh", privileged: false
  end

  config.vm.define "ovs" do |ovs|
    ovs.vm.box = "generic/ubuntu1804"
    ovs.vm.network :private_network, :ip => "192.168.254.21"
    ovs.vm.provision :shell, :path => "scripts/ovs.sh", privileged:false
  end

  config.vm.define "ids1" do |ids1|
    ids1.vm.box = "generic/ubuntu1804"
    ids1.vm.network :private_network, :ip => "192.168.254.61"
    ids1.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids1.vm.provision "file", source: "./sources/binary_flow_ids", destination: "/home/vagrant/"
    ids1.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids2" do |ids2|
    ids2.vm.box = "generic/ubuntu1804"
    ids2.vm.network :private_network, :ip => "192.168.254.62"
    ids2.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids2.vm.provision "file", source: "./sources/binary_flow_ids", destination: "/home/vagrant/"
    ids2.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

end