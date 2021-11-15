sudo DEBIAN_FRONTEND=noninteractive apt update -y -q
sudo DEBIAN_FRONTEND=noninteractive apt install openjdk-11-jre -y -q
tar -xzf opendaylight-0.12.3.tar.gz
sed  -e '/featuresBoot =/s/$/,service-wrapper,odl-restconf,odl-mdsal-apidocs,odl-openflowplugin-flow-services,odl-openflowplugin-app-table-miss-enforcer,odl-openflowplugin-nxm-extensions,odl-restconf-all,odl-openflowplugin-flow-services/' opendaylight-0.12.3/etc/org.apache.karaf.features.cfg -i
sudo ./opendaylight-0.12.3/bin/start
sudo cp odl.service /etc/systemd/system/
sudo systemctl enable odl.service