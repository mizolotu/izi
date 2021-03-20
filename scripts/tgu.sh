sudo apt update -y
sudo apt install openvswitch-switch tcpreplay python3-pip -y
sudo ovs-vsctl add-br br
sudo ovs-ofctl del-flows br
pip3 install -U pip
pip3 install -U setuptools
pip3 install flask numpy pandas
sudo cp tgu.service /etc/systemd/system/
sudo systemctl enable tgu
sudo systemctl start tgu