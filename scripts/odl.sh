sudo apt update -y
tar -xzf opendaylight-0.12.2.tar.gz
sudo apt-get -y install openjdk-11-jre
sed  -e '/featuresBoot =/s/$/,service-wrapper,odl-restconf,odl-mdsal-apidocs,odl-openflowplugin-flow-services,odl-openflowplugin-app-table-miss-enforcer,odl-openflowplugin-nxm-extensions,odl-restconf-all,odl-openflowplugin-flow-services/' opendaylight-0.12.2/etc/org.apache.karaf.features.cfg -i
sudo ./opendaylight-0.12.2/bin/start
sudo cp odl.service /etc/systemd/system/
sudo systemctl enable odl.service
