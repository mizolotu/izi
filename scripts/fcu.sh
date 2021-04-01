sudo apt update -y
sudo apt install python3-pip -y
pip3 install -U pip
pip3 install -U setuptools
pip3 install flask
sudo cp fcu.service /etc/systemd/system/
sudo systemctl enable fcu
sudo systemctl start fcu