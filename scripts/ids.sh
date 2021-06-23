sudo apt update -y
sudo apt install libpcap-dev openvswitch-switch -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential python3-dev libpcap-dev netfilter-persistent python3-pip
sudo ovs-vsctl add-br br
sudo ovs-ofctl del-flows br
pip3 install -U pip
pip3 install -U setuptools
sudo /usr/bin/python3 -m pip install pandas pyyaml h5py flask pypcap kaitaistruct scapy
sudo /usr/bin/python3 -m pip install --extra-index-url https://google-coral.github.io/py-repo/ tflite_runtime
sudo cp ids.service /etc/systemd/system/
sudo systemctl enable ids
sudo systemctl start ids