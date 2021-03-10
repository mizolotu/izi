sudo apt update -y
sudo apt install libpcap-dev openvswitch-switch -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential python3-dev libpcap-dev netfilter-persistent python3-pip
sudo ovs-vsctl add-br br
sudo ovs-ofctl del-flows br
pip3 install -U pip
pip3 install -U setuptools
pip3 install pandas pyyaml h5py flask pypcap kaitaistruct
pip3 install https://github.com/google-coral/pycoral/releases/download/release-frogfish/tflite_runtime-2.5.0-cp36-cp36m-linux_x86_64.whl
sudo cp ids.service /etc/systemd/system/
sudo systemctl enable ids
sudo systemctl start ids