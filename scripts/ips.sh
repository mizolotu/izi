sudo apt update -y
sudo apt install libpcap-dev openvswitch-switch -y
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q build-essential python3-dev libpcap-dev python3-pip libnetfilter-queue-dev iptables-persistent netfilter-persistent
sudo ovs-vsctl add-br br
sudo ovs-ofctl del-flows br
pip3 install -U pip
pip3 install -U setuptools
sudo /usr/bin/python3 -m pip install pandas pyyaml h5py flask pypcap kaitaistruct scapy NetfilterQueue
sudo /usr/bin/python3 -m pip install --extra-index-url https://google-coral.github.io/py-repo/ tflite_runtime
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
sudo iptables -A FORWARD -j NFQUEUE --queue-num 0
sudo netfilter-persistent save
sudo netfilter-persistent start
sudo cp ips.service /etc/systemd/system/
sudo systemctl enable ips
sudo systemctl start ips