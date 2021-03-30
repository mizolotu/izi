sudo apt update -y
sudo apt install openvswitch-switch -y
sudo ovs-vsctl add-br br
sudo ovs-vsctl set-controller br tcp:192.168.254.11:6653
sudo ovs-ofctl del-flows br
sudo ovs-vsctl -- --id=@sflow create sflow agent=eth1 target="\"192.168.254.1:6343\"" header=128 polling=1 sampling=1 -- set bridge br sflow=@sflow
