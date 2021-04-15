sudo apt update -y
sudo apt install openvswitch-switch tcpreplay libpcap-dev python3-pip -y
sudo ovs-vsctl add-br br
sudo ovs-ofctl del-flows br
pip3 install -U pip
pip3 install -U setuptools
pip3 install flask numpy pandas kaitaistruct pypcap
sudo cp ovs.service /etc/systemd/system/
sudo systemctl enable ovs
sudo systemctl start ovs