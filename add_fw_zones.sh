firewall-cmd --zone=home --add-service=rpc-bind
firewall-cmd --zone=home --add-port=2049/tcp
firewall-cmd --zone=home --add-port=20048/udp