sudo apt update -y
sudo apt install openvswitch-switch -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential python3-dev libnetfilter-queue-dev libpcap-dev iptables-persistent netfilter-persistent python3-pip
sudo ovs-vsctl add-br br
sudo ovs-vsctl set-controller br tcp:192.168.254.11:6653
sudo ovs-ofctl del-flows br
pip3 install -U pip
pip3 install -U setuptools
pip3 install scapy NetfilterQueue pandas pyyaml h5py flask
pip3 install https://github.com/google-coral/pycoral/releases/download/release-frogfish/tflite_runtime-2.5.0-cp36-cp36m-linux_x86_64.whl
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0
sudo netfilter-persistent save
sudo netfilter-persistent start
sudo cp ids.service /etc/systemd/system/
sudo systemctl enable ids
sudo systemctl start ids