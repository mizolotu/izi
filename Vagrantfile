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

  config.vm.define "odl_1", primary: true do |odl_1|
    odl_1.vm.box = "generic/ubuntu1804"
    odl_1.vm.network :private_network, :ip => "192.168.254.11"
    odl_1.vm.provision "file", source: "sources/opendaylight-0.12.3.tar.gz", destination: "opendaylight-0.12.3.tar.gz"
    odl_1.vm.provision "file", source: "sources/odl.service", destination: "/home/vagrant/"
    odl_1.vm.provision :shell, :path => "scripts/odl.sh", privileged: false
  end

  config.vm.define "ovs_1" do |ovs_1|
    ovs_1.vm.box = "generic/ubuntu1804"
    ovs_1.vm.network :private_network, :ip => "192.168.254.12"
    ovs_1.vm.network :private_network, :ip => "10.0.0.12"
    ovs_1.vm.provision :shell, :path => "scripts/ovs.sh", privileged:false
  end

  config.vm.define "ids_1_1" do |ids_1_1|
    ids_1_1.vm.box = "generic/ubuntu1804"
    ids_1_1.vm.network :private_network, :ip => "192.168.254.61"
    ids_1_1.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_1_1.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_1_1.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids_1_2" do |ids_1_2|
    ids_1_2.vm.box = "generic/ubuntu1804"
    ids_1_2.vm.network :private_network, :ip => "192.168.254.62"
    ids_1_2.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_1_2.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_1_2.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

end