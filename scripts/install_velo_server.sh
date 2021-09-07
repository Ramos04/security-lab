#!/bin/bash
##################################################
# Download and install velociraptor server
#
# Installs in /opt/velociraptor
#
# Ensure the server and client configs are 
# installed in: /opt/velociraptor/etc/*.config.yaml
#  - The service unit file wont work otherwise
#
##################################################

host_ip=$(hostname -I | awk '{print $1}')
user_shell_rc="/home/$(logname)/.$(basename $SHELL)rc"

# velociraptor $HOME paths
velo_dir=/opt/velociraptor
velo_bin_dir="$velo_dir/bin"
velo_log_dir="$velo_dir/logs"
velo_etc_dir="$velo_dir/etc"
velo_bin_exe="$velo_bin_dir/velociraptor"

# configuration paths
velo_server_conf="$velo_etc_dir/server.config.yaml"
velo_client_conf="$velo_etc_dir/client.config.yaml"

# service variables
velo_service_file="/lib/systemd/system/velociraptor.service"
velo_service_contents="[Unit]\nDescription=Velociraptor linux amd64\nAfter=syslog.target network.target\n\n[Service]\nType=simple\nRestart=always\nRestartSec=120\nLimitNOFILE=20000\nEnvironment=LANG=en_US.UTF-8\nExecStart=/opt/velociraptor/bin/velociraptor --config /opt/velociraptor/etc/server.config.yaml frontend -v\n\n[Install]\nWantedBy=multi-user.target"

err_report() {
    rm -rf $velo_dir $velo_service_file
    exit 1
}

trap 'err_report' SIGINT SIGTERM

# bash check
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

# check if velociraptor exists
if [ -d "$velo_dir" ]; then
	echo "$velo_dir already exists, this will overwrite it."
	read -p "Overwrite old directory? (y/n) " -n 1 -r

	if [[ $REPLY =~ ^[Yy]$ ]]; then
		echo ""
		echo "Removing old $velo_dir"
		rm -Rf $velo_dir
	else
		exit 1
	fi
fi

systemctl list-units | grep "velociraptor" 1> /dev/null

if [[ $? -eq 0 ]]; then
	echo "stopping velociraptor service"
	systemctl stop velociraptor

	echo "disabling velociraptor service"
	system disable velociraptor
fi

# create velo directories
echo "Creating $velo_dir"
mkdir $velo_dir $velo_bin_dir $velo_log_dir $velo_etc_dir #$velo_datastore_dir

# download latest release
echo "Downloading latest $(uname) release"
curl -sL https://github.com/velocidex/velociraptor/releases/latest \
	| grep -i $(uname) \
	| head -n1 \
	| sed -n 's/.*href="\([^"]*\).*/\1/p' \
	| awk '{ print "https://github.com/"$0; }' \
	| wget -i - -O "$velo_bin_exe"

echo "Setting velociraptor binary to executable"
chmod +x "$velo_bin_exe"

# add path to bashrc
grep "/opt/Velociraptor/bin" $user_shell_rc > /dev/null

if [[ $? -eq 1 ]]; then
	echo "Adding path to $user_shell_rc"
	echo $'\nexport PATH=/opt/Velociraptor/bin:$PATH' >> "$user_shell_rc"
fi
echo "+------------------------------------------+"
echo "| FOR COPY PASTE EASE OF USE"
echo "+------------------------------------------+"
echo "| SERVER CONF: $velo_server_conf"
echo "| CLIENT CONF: $velo_client_conf"
echo "+------------------------------------------+"

echo "Create config"
$velo_bin_exe config generate -i

# set correct owner
echo "Setting directory owner"
chown root:root $velo_dir

# set correct permissions
echo "Setting directory permissions"
sudo chmod -R 0755 $velo_dir

# replace 127.0.0.1
echo "Replace 127.0.0.1 with $host_ip in confs"
sed -i "s/127.0.0.1/$host_ip/g" $velo_server_conf
sed -i "s/https:\/\/localhost:8000\//https:\/\/$host_ip:8000\//g" $velo_server_conf
sed -i "s/hostname: localhost//g" $velo_server_conf

echo "Creating velociraptor service file"
printf "$velo_service_contents" > $velo_service_file
systemctl daemon-reload
systemctl enable velociraptor

echo "starting velociraptor service"
systemctl start velociraptor
systemctl status velociraptor
