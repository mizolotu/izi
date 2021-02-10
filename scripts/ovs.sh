sudo apt update -y
sudo apt install openvswitch-switch -y
sudo ovs-vsctl add-br br
sudo ovs-vsctl set-controller br tcp:192.168.254.11:6653
sudo ovs-ofctl del-flows br
sudo apt install apt-transport-https ca-certificates curl software-properties-common -y
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable" -y
sudo apt update -y
sudo apt install docker-ce -y
sudo sed -e '/ExecStart/s/$/ -H=tcp:\/\/0.0.0.0:2375/' /lib/systemd/system/docker.service -i
sudo systemctl daemon-reload
sudo service docker restart
