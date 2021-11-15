sudo DEBIAN_FRONTEND=noninteractive apt update -y -q
sudo DEBIAN_FRONTEND=noninteractive apt install openvswitch-switch libpcap-dev python3-pip -y -q
pip3 install -U pip
pip3 install -U setuptools
sudo /usr/bin/python3 -m pip install flask numpy pandas pypcap pypacker
sudo ovs-vsctl add-br br
sudo ovs-ofctl del-flows br
sudo cp ovs.service /etc/systemd/system/
sudo systemctl enable ovs
sudo systemctl start ovs