sudo apt update -y
sudo apt install openvswitch-switch -y
sudo ovs-vsctl add-br br
#sudo ovs-vsctl add-port br eth2
#sudo ifconfig eth2 0
sudo ovs-vsctl set-controller br tcp:192.168.254.11:6653
sudo ovs-ofctl del-flows br
