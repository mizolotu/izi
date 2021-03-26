# -*- mode: ruby -*-
# vi: set ft=ruby :

# Use libvirt (qemu/kvm) to run virtual machine
ENV['VAGRANT_DEFAULT_PROVIDER'] = 'libvirt'

Vagrant.configure("2") do |config|

  # Define libvirt storage pool to use
  config.vm.provider :libvirt do |libvirt|
    #libvirt.storage_pool_name = "images-1"
    libvirt.management_network_name = "default"
    libvirt.management_network_address = "192.168.122.0/24"
  end

  config.vm.define "tgu", primary: true do |tgu|
    tgu.vm.box = "generic/ubuntu1804"
    tgu.vm.network :private_network, :ip => "192.168.254.10"
    tgu.vm.network :private_network, :ip => "100.0.0.10"
    tgu.vm.provision "file", source: "./sources/tgu.service", destination: "/home/vagrant/"
    tgu.vm.provision "file", source: "./sources/tgu", destination: "/home/vagrant/"
    tgu.vm.provision :shell, :path => "scripts/tgu.sh", privileged: false
    tgu.vm.synced_folder './data/spl', '/home/vagrant/data/spl', type: 'nfs', nfs_udp: false
  end

  config.vm.define "odl", primary: true do |odl|
    odl.vm.box = "generic/ubuntu1804"
    odl.vm.network :private_network, :ip => "192.168.254.11"
    odl.vm.provision "file", source: "./sources/opendaylight-0.12.3.tar.gz", destination: "opendaylight-0.12.3.tar.gz"
    odl.vm.provision "file", source: "./sources/odl.service", destination: "/home/vagrant/"
    odl.vm.provision :shell, :path => "scripts/odl.sh", privileged: false
  end

  config.vm.define "ovs_0" do |ovs_0|
    ovs_0.vm.box = "generic/ubuntu1804"
    ovs_0.vm.network :private_network, :ip => "192.168.254.20"
    ovs_0.vm.network :private_network, :ip => "100.0.0.20"
    ovs_0.vm.provision :shell, :path => "scripts/ovs.sh", privileged:false
  end

  config.vm.define "ovs_1" do |ovs_1|
    ovs_1.vm.box = "generic/ubuntu1804"
    ovs_1.vm.network :private_network, :ip => "192.168.254.21"
    ovs_1.vm.network :private_network, :ip => "100.0.0.21"
    ovs_1.vm.provision :shell, :path => "scripts/ovs.sh", privileged:false
  end

  config.vm.define "ovs_2" do |ovs_2|
    ovs_2.vm.box = "generic/ubuntu1804"
    ovs_2.vm.network :private_network, :ip => "192.168.254.22"
    ovs_2.vm.network :private_network, :ip => "100.0.0.22"
    ovs_2.vm.provision :shell, :path => "scripts/ovs.sh", privileged:false
  end

  config.vm.define "ovs_3" do |ovs_3|
    ovs_3.vm.box = "generic/ubuntu1804"
    ovs_3.vm.network :private_network, :ip => "192.168.254.23"
    ovs_3.vm.network :private_network, :ip => "100.0.0.23"
    ovs_3.vm.provision :shell, :path => "scripts/ovs.sh", privileged:false
  end

  config.vm.define "ids_0_0" do |ids_0_0|
    ids_0_0.vm.box = "generic/ubuntu1804"
    ids_0_0.vm.network :private_network, :ip => "192.168.254.60"
    ids_0_0.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_0_0.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_0_0.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids_0_1" do |ids_0_1|
    ids_0_1.vm.box = "generic/ubuntu1804"
    ids_0_1.vm.network :private_network, :ip => "192.168.254.61"
    ids_0_1.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_0_1.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_0_1.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids_1_0" do |ids_1_0|
    ids_1_0.vm.box = "generic/ubuntu1804"
    ids_1_0.vm.network :private_network, :ip => "192.168.254.62"
    ids_1_0.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_1_0.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_1_0.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids_1_1" do |ids_1_1|
    ids_1_1.vm.box = "generic/ubuntu1804"
    ids_1_1.vm.network :private_network, :ip => "192.168.254.63"
    ids_1_1.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_1_1.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_1_1.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

config.vm.define "ids_2_0" do |ids_2_0|
    ids_2_0.vm.box = "generic/ubuntu1804"
    ids_2_0.vm.network :private_network, :ip => "192.168.254.64"
    ids_2_0.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_2_0.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_2_0.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids_2_1" do |ids_2_1|
    ids_2_1.vm.box = "generic/ubuntu1804"
    ids_2_1.vm.network :private_network, :ip => "192.168.254.65"
    ids_2_1.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_2_1.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_2_1.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids_3_0" do |ids_3_0|
    ids_3_0.vm.box = "generic/ubuntu1804"
    ids_3_0.vm.network :private_network, :ip => "192.168.254.66"
    ids_3_0.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_3_0.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_3_0.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

  config.vm.define "ids_3_1" do |ids_3_1|
    ids_3_1.vm.box = "generic/ubuntu1804"
    ids_3_1.vm.network :private_network, :ip => "192.168.254.67"
    ids_3_1.vm.provision "file", source: "./sources/ids.service", destination: "/home/vagrant/"
    ids_3_1.vm.provision "file", source: "./sources/ids", destination: "/home/vagrant/"
    ids_3_1.vm.provision :shell, :path => "scripts/ids.sh", privileged:false
  end

end