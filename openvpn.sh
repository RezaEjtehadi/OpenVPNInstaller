#!/bin/bash
RADIUS="49.12.203.127"
SECRET="set"
PORTUDP=9000
PORTTCP=9001
CLIENT="OpenVPN-Profile"
GROUPNAME=nobody

newclient () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common.txt ~/$1.ovpn
	echo "<ca>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn
	echo "</ca>" >> ~/$1.ovpn
	echo "<cert>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn
	echo "</cert>" >> ~/$1.ovpn
	echo "<key>" >> ~/$1.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn
	echo "</key>" >> ~/$1.ovpn
	echo "<tls-auth>" >> ~/$1.ovpn
	cat /etc/openvpn/ta.key >> ~/$1.ovpn
	echo "</tls-auth>" >> ~/$1.ovpn
}
newclienttcp () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common-tcp.txt ~/$1-tcp.ovpn
	echo "<ca>" >> ~/$1-tcp.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1-tcp.ovpn
	echo "</ca>" >> ~/$1-tcp.ovpn
	echo "<cert>" >> ~/$1-tcp.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1-tcp.ovpn
	echo "</cert>" >> ~/$1-tcp.ovpn
	echo "<key>" >> ~/$1-tcp.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1-tcp.ovpn
	echo "</key>" >> ~/$1-tcp.ovpn
	echo "<tls-auth>" >> ~/$1-tcp.ovpn
	cat /etc/openvpn/ta.key >> ~/$1-tcp.ovpn
	echo "</tls-auth>" >> ~/$1-tcp.ovpn
}
newclientudp () {
	# Generates the custom client.ovpn
	cp /etc/openvpn/client-common-udp.txt ~/$1-udp.ovpn
	echo "<ca>" >> ~/$1-udp.ovpn
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1-udp.ovpn
	echo "</ca>" >> ~/$1-udp.ovpn
	echo "<cert>" >> ~/$1-udp.ovpn
	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1-udp.ovpn
	echo "</cert>" >> ~/$1-udp.ovpn
	echo "<key>" >> ~/$1-udp.ovpn
	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1-udp.ovpn
	echo "</key>" >> ~/$1-udp.ovpn
	echo "<tls-auth>" >> ~/$1-udp.ovpn
	cat /etc/openvpn/ta.key >> ~/$1-udp.ovpn
	echo "</tls-auth>" >> ~/$1-udp.ovpn
}


IPv6="fc00::/7"
IP=$(wget -4qO- "http://whatismyip.akamai.com/")
yum update -y
yum install epel-release -y
yum install openvpn iptables firewalld openssl wget ca-certificates -y
wget --user registry --password speed@123 http://registry.ibsspeed.in/OpenVPN/radiusplugin.so -O ~/radiusplugin.so
wget --user registry --password speed@123 http://registry.ibsspeed.in/OpenVPN/radiusplugin.conf -O ~/radiusplugin.conf
cp ~/radiusplugin.so /etc/openvpn/
cp ~/radiusplugin.conf /etc/openvpn/
IFS='/' read -r -a IP6 <<< "$IPv6"
sed -i "s/#radiusip/$RADIUS/g" "/etc/openvpn/radiusplugin.conf"
sed -i "s/#secret/$SECRET/g" "/etc/openvpn/radiusplugin.conf"
sed -i "s/#nas/$IP/g" "/etc/openvpn/radiusplugin.conf"


wget -O ~/EasyRSA-3.0.4.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.4/EasyRSA-3.0.4.tgz"
tar xzf ~/EasyRSA-3.0.4.tgz -C ~/
mv ~/EasyRSA-3.0.4/ /etc/openvpn/
mv /etc/openvpn/EasyRSA-3.0.4/ /etc/openvpn/easy-rsa/
rm -rf ~/EasyRSA-3.0.4.tgz
cd /etc/openvpn/easy-rsa/


./easyrsa init-pki
EASYRSA_REQ_CN="DigitalSoftwareSolutions" ./easyrsa --batch build-ca nopass
./easyrsa gen-dh
./easyrsa build-server-full server nopass
./easyrsa build-client-full $CLIENT nopass
EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn

chown nobody:$GROUPNAME /etc/openvpn/crl.pem

openvpn --genkey --secret /etc/openvpn/ta.key


echo "port $PORTUDP
proto udp
dev tun0
tun-ipv6
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
server-ipv6 ${IP6[0]}8000:0/112
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server.conf

echo "ifconfig-ipv6 ${IP6[0]}8000:1 ${IP6[0]}8000:2" >> /etc/openvpn/server.conf
echo "push \"route-ipv6 ${IP6[0]}8000:2/112\"" >> /etc/openvpn/server.conf
echo "push \"route-ipv6 2000::/3\"" >> /etc/openvpn/server.conf
echo 'push "redirect-gateway ipv6 def1 bypass-dhcp"' >> /etc/openvpn/server.conf
echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server.conf
echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server.conf
echo 'push "dhcp-option DNS6 2001:4860:4860::8888"' >> /etc/openvpn/server.conf
echo 'push "dhcp-option DNS6 2001:4860:4860::8844"' >> /etc/openvpn/server.conf
echo "keepalive 10 120
username-as-common-name
duplicate-cn
cipher AES-128-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
verb 3
crl-verify crl.pem
log log.log
plugin /etc/openvpn/radiusplugin.so  /etc/openvpn/radiusplugin.conf" >> /etc/openvpn/server.conf

echo "port $PORTTCP
proto tcp
dev tun1
tun-ipv6
sndbuf 0
rcvbuf 0
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-auth ta.key 0
topology subnet
server 10.8.1.0 255.255.255.0
server-ipv6 ${IP6[0]}8100:0/112
ifconfig-pool-persist ipp.txt" > /etc/openvpn/server2.conf
echo "push \"route-ipv6 2000::/3\"" >> /etc/openvpn/server2.conf
echo 'push "redirect-gateway ipv6 def1 bypass-dhcp"' >> /etc/openvpn/server2.conf
echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/server2.conf
echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/server2.conf
echo 'push "dhcp-option DNS6 2001:4860:4860::8888"' >> /etc/openvpn/server2.conf
echo 'push "dhcp-option DNS6 2001:4860:4860::8844"' >> /etc/openvpn/server2.conf
echo "keepalive 10 120
username-as-common-name
duplicate-cn
cipher AES-128-CBC
comp-lzo
user nobody
group $GROUPNAME
persist-key
persist-tun
verb 3
crl-verify crl.pem
log log-tcp.log
plugin /etc/openvpn/radiusplugin.so  /etc/openvpn/radiusplugin.conf" >> /etc/openvpn/server2.conf
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.all.accept_ra=2
sysctl -w net.ipv6.conf.all.proxy_ndp=1
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.all.accept_redirects=0


systemctl enable firewalld
systemctl start firewalld
# We don't use --add-service=openvpn because that would only work with
# the default port. Using both permanent and not permanent rules to
# avoid a firewalld reload.
firewall-cmd --permanent --add-port=$PORTUDP/udp
firewall-cmd --permanent --add-port=$PORTTCP/tcp
firewall-cmd --zone=public --add-port=$PORTUDP/udp
firewall-cmd --zone=trusted --add-source=10.8.0.0/24
firewall-cmd --zone=public --add-port=$PORTTCP/tcp
firewall-cmd --zone=trusted --add-source=10.8.1.0/24
firewall-cmd --permanent --zone=public --add-port=$PORTUDP/udp
firewall-cmd --permanent --zone=trusted --add-source=10.8.0.0/24
firewall-cmd --permanent --zone=public --add-port=$PORTTCP/tcp
firewall-cmd --permanent --zone=trusted --add-source=10.8.1.0/24
# Set NAT for the VPN subnet (UDP)
firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
# Set NAT for the VPN subnet (TCP)
firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.1.0/24 ! -d 10.8.1.0/24 -j SNAT --to $IP
firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.8.1.0/24 ! -d 10.8.1.0/24 -j SNAT --to $IP
firewall-cmd --zone=trusted --add-source=$IPv6
firewall-cmd --permanent --zone=trusted --add-source=$IPv6
firewall-cmd --direct --add-rule ipv6 filter FORWARD 0 -i sit1 -j ACCEPT
firewall-cmd --direct --permanent --add-rule ipv6 filter FORWARD 0 -i sit1 -j ACCEPT
firewall-cmd --reload
if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if ! hash semanage 2>/dev/null; then
					yum install policycoreutils-python -y
				fi
				semanage port -a -t openvpn_port_t -p tcp $PORTTCP
				semanage port -a -t openvpn_port_t -p udp $PORTUDP
		fi
	fi
echo "client
dev tun
proto udp
sndbuf 0
rcvbuf 0
remote $IP $PORTUDP
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-128-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3
auth-user-pass" > /etc/openvpn/client-common-udp.txt
echo "client
dev tun
proto tcp
sndbuf 0
rcvbuf 0
remote $IP $PORTTCP
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher AES-128-CBC
comp-lzo
setenv opt block-outside-dns
key-direction 1
verb 3
auth-user-pass" > /etc/openvpn/client-common-tcp.txt

newclientudp "$CLIENT"
newclienttcp "$CLIENT"
echo ""
echo "Finished!"
echo ""
echo "Your client TCP config is available at ~/$CLIENT-tcp.ovpn"
echo "Your client UDP config is available at ~/$CLIENT-udp.ovpn"
rm -rf ~/radiusplugin.conf
rm -rf ~/radiusplugin.so
systemctl enable openvpn@server
service openvpn@server start 
systemctl enable openvpn@server2
service openvpn@server2 start 
