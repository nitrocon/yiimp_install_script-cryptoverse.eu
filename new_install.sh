#!/bin/bash

################################################################################
# Original Author: crombiecrunch
# Modified by: nitrocon (https://github.com/nitrocon) Web: https://pool.cryptoverse.eu
#
# Program:
#   Install yiimp on Ubuntu 16.04/18.04 running Nginx, MariaDB, and php7.3
#   cryptoverse.eu (update November, 2022)
#
################################################################################

# Function to display error message in yellow color
function displayErr() {
  echo -e "\e[33mError: $1\e[0m" >&2
  exit 1
}

# Function to print colored text
function print_color() {
  local color_code=$1
  local message=$2
  echo -e "\e[${color_code}m${message}\e[0m"
}

# Function to install packages with error handling
function install_packages() {
  sudo apt -y install "$@" || displayErr "Failed to install packages: $*"
}

# Add user to sudo group without password prompt
sudo usermod -aG sudo "$(whoami)" || displayErr "Failed to add user to sudo group."
echo "$(whoami) ALL=(ALL) NOPASSWD:ALL" | sudo tee "/etc/sudoers.d/$(whoami)" >/dev/null 2>&1 || displayErr "Failed to update sudoers file."

# Copy required files
sudo cp -r "conf/functions.sh" "/etc/" || displayErr "Failed to copy functions.sh file."
sudo cp -r "utils/screen-scrypt.sh" "/etc/" || displayErr "Failed to copy screen-scrypt.sh file."
sudo cp -r "conf/editconf.py" "/usr/bin/" || displayErr "Failed to copy editconf.py file."
sudo chmod +x "/usr/bin/editconf.py" || displayErr "Failed to set execute permission for editconf.py."
sudo chmod +x "/etc/screen-scrypt.sh" || displayErr "Failed to set execute permission for screen-scrypt.sh."

# Source the functions file
source "/etc/functions.sh" || displayErr "Failed to source functions.sh file."

clear

echo
print_color "35" "Yiimp Install Script cryptoverse.eu"
print_color "35" "Install yiimp on Ubuntu 16.04/18.04 running Nginx, MariaDB, and php7.3"
echo
sleep 3

# Update system and install required packages
echo -e "\n\n=> Updating system and installing required packages:\n"
sleep 3
        
sudo apt-get -qq update || displayErr "Failed to update system packages."
sudo apt-get -qq upgrade || displayErr "Failed to upgrade system packages."
sudo apt-get -qq autoremove || displayErr "Failed to remove unnecessary packages."
sudo apt-get -qq install -y software-properties-common dialog python3 python3-pip acl nano apt-transport-https || displayErr "Failed to install required packages."
print_color "32" "Done..."

source conf/prerequisite.sh || displayErr "Failed to source prerequisite.sh file."
sleep 3
source conf/getip.sh || displayErr "Failed to source getip.sh file."

# Set Public IP in pool.conf
echo "PUBLIC_IP='${PUBLIC_IP}'" | sudo -E tee conf/pool.conf >/dev/null 2>&1 || displayErr "Failed to set PUBLIC_IP in pool.conf."

echo
echo
echo -e "\e[31mMake sure you double check before hitting enter! Only one shot at these!\e[0m"
echo

read -e -p "Domain Name (no http:// or www. just: example.com or pool.example.com or 185.22.24.26): " server_name || displayErr "Failed to read domain name."
read -e -p "Are you using a subdomain (mycryptopool.example.com?) [y/N]: " sub_domain || displayErr "Failed to read subdomain option."
read -e -p "Enter support email (e.g. admin@example.com): " EMAIL || displayErr "Failed to read support email."
read -e -p "Set Pool to AutoExchange? i.e. mine any coin with BTC address? [y/N]: " BTC || displayErr "Failed to read AutoExchange option."
read -e -p "Enter the Public IP of the system you will use to access the admin panel (http://www.whatsmyip.org/): " Public || displayErr "Failed to read Public IP."
read -e -p "Install Fail2ban? [Y/n]: " install_fail2ban || displayErr "Failed to read Fail2ban option."
read -e -p "Install UFW and configure ports? [Y/n]: " UFW || displayErr "Failed to read UFW option."
read -e -p "Install LetsEncrypt SSL? IMPORTANT! You MUST have your domain name pointed to this server prior to running the script!! [Y/n]: " ssl_install || displayErr "Failed to read SSL installation option."

# Installing Nginx
echo
echo
print_color "36" "=> Installing Nginx server :"
echo
sleep 3

if [ -f /usr/sbin/apache2 ]; then
  echo -e "\e[32mRemoving apache...\e[0m"
  sudo apt-get -y purge apache2 apache2-* || displayErr "\e[31mFailed to remove apache.\e[0m"
  sudo apt-get -y --purge autoremove || displayErr "\e[31mFailed to remove unnecessary packages.\e[0m"
fi

sudo apt -y install nginx || displayErr "\e[31mFailed to install Nginx.\e[0m"
sudo rm /etc/nginx/sites-enabled/default || displayErr "\e[31mFailed to remove default Nginx site.\e[0m"
sudo systemctl start nginx.service || displayErr "\e[31mFailed to start Nginx service.\e[0m"
sudo systemctl enable nginx.service || displayErr "\e[31mFailed to enable Nginx service.\e[0m"
sudo systemctl start cron.service || displayErr "\e[31mFailed to start cron service.\e[0m"
sudo systemctl enable cron.service || displayErr "\e[31mFailed to enable cron service.\e[0m"
sleep 5
sudo systemctl status nginx | sed -n "1,3p" || displayErr "\e[31mFailed to get Nginx service status.\e[0m"
sleep 15
echo
print_color "32" "Done..."

# Making Nginx a bit hard
echo 'map $http_user_agent $blockedagent {
default         0;
~*malicious     1;
~*bot           1;
~*backdoor      1;
~*crawler       1;
~*bandit        1;
}
' | sudo -E tee /etc/nginx/blockuseragents.rules >/dev/null 2>&1 || displayErr "Failed to create blockuseragents.rules file."

print_color "32" "Nginx configuration updated."

# Installing Mariadb
echo
echo
print_color "36" "=> Installing MariaDB Server:"
echo
sleep 3

# Create random password
rootpasswd=$(openssl rand -base64 12)
export DEBIAN_FRONTEND="noninteractive"
sudo apt -y install mariadb-server || displayErr "Failed to install MariaDB Server."
sudo systemctl enable mariadb.service
sudo systemctl start mariadb.service
sleep 5
sudo systemctl status mariadb | sed -n "1,3p"
sleep 15
echo
print_color "32" "Done..."

# Installing PHP
php_version="7.3"
print_color "36" "=> Installing PHP $php_version:"
sleep 3

source conf/pool.conf || displayErr "Failed to source pool.conf file."

[ ! -f /etc/apt/sources.list.d/ondrej-php-bionic.list ] && sudo add-apt-repository -y ppa:ondrej/php
sudo apt -y update || displayErr "Failed to update packages."

packages=(
  "php${php_version}-fpm" "php${php_version}-opcache" "php${php_version}" "php${php_version}-common" "php${php_version}-gd"
  "php${php_version}-mysql" "php${php_version}-imap" "php${php_version}-cli" "php${php_version}-cgi" "php-pear"
  "imagemagick" "libruby" "php${php_version}-curl" "php${php_version}-intl" "php${php_version}-pspell" "mcrypt"
  "php${php_version}-recode" "php${php_version}-sqlite3" "php${php_version}-tidy" "php${php_version}-xmlrpc"
  "php${php_version}-xsl" "memcached" "php-memcache" "php-imagick" "php-gettext" "php${php_version}-zip"
  "php${php_version}-mbstring"
)

[[ "$DISTRO" != "16" ]] && packages+=("php${php_version}-memcache" "php${php_version}-memcached")

install_packages "${packages[@]}"
sleep 5

sudo systemctl start php${php_version}-fpm
sudo systemctl status php${php_version}-fpm | sed -n "1,3p"
sleep 15

print_color "32" "Done..."

# Installing other needed files
print_color "36" "=> Installing other needed files:"
echo
sleep 3

install_packages libgmp3-dev libmysqlclient-dev libcurl4-gnutls-dev libkrb5-dev libldap2-dev libidn11-dev gnutls-dev \
  librtmp-dev sendmail mutt screen git
install_packages pwgen -y
print_color "32" "Done..."
sleep 3

# Installing Package to compile crypto currency
print_color "36" "=> Installing Package to compile crypto currency:"
echo
sleep 3

install_packages software-properties-common build-essential
install_packages libtool autotools-dev automake pkg-config libssl-dev libevent-dev bsdmainutils git cmake libboost-all-dev \
  zlib1g-dev libz-dev libseccomp-dev libcap-dev libminiupnpc-dev gettext
install_packages libminiupnpc10 libzmq5
install_packages libcanberra-gtk-module libqrencode-dev libzmq3-dev
install_packages libqt5gui5 libqt5core5a libqt5webkit5-dev libqt5dbus5 qttools5-dev qttools5-dev-tools libprotobuf-dev \
  protobuf-compiler
sudo add-apt-repository -y ppa:bitcoin/bitcoin
sudo apt -y update
install_packages libdb4.8-dev libdb4.8++-dev libdb5.3 libdb5.3++
print_color "32" "Done..."

# Generating Random Passwords
password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
password2=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
AUTOGENERATED_PASS=$(pwgen -c -1 20)

# Test Email
print_color "36" "=> Testing to see if server emails are sent:"
sleep 3

if [[ "$root_email" != "" ]]; then
  echo "$root_email" | sudo tee --append ~/.email
  echo "$root_email" | sudo tee --append ~/.forward

  if [[ "$send_email" =~ ^[Yy]$ || -z "$send_email" ]]; then
    echo "This is a mail test for the SMTP Service." | sudo tee --append /tmp/email.message
    echo "You should receive this!" | sudo tee --append /tmp/email.message
    echo "" | sudo tee --append /tmp/email.message
    echo "Cheers" | sudo tee --append /tmp/email.message

    sudo sendmail -s "SMTP Testing" "$root_email" < /tmp/email.message || displayErr "Failed to send test email"

    sudo rm -f /tmp/email.message
    print_color "32" "Mail sent"
  fi
fi

print_color "32" "Done..."

# Installing Fail2Ban & UFW
print_color "36" "=> Some optional installs (Fail2Ban & UFW):"
sleep 3

if [[ "$install_fail2ban" =~ ^[Yy]$ || -z "$install_fail2ban" ]]; then
  install_packages fail2ban
  sleep 5
  sudo systemctl status fail2ban | sed -n "1,3p"
fi

if [[ "$UFW" =~ ^[Yy]$ || -z "$UFW" ]]; then
  install_packages ufw

  # Allow specific ports
  allowed_ports=(
    3333 3339 3334 3433 3555 3556 3573 3535 3533 3553 3633 3733 3636 3737 3739 3747 3833 3933 4033 4133 4233
    4234 4333 4433 4533 4553 4633 4733 4833 4933 5033 5133 5233 5333 5433 5533 5733 5743 3252 5755 5766 5833
    5933 6033 5034 6133 6233 6333 6433 7433 7070 8333 8463 8433 8533
  )

  # Allow SSH, HTTP, and HTTPS
  allowed_services=("ssh" "http" "https")

  for port in "${allowed_ports[@]}"; do
    sudo ufw allow "$port/tcp"
  done

  for service in "${allowed_services[@]}"; do
    sudo ufw allow "$service"
  done

  sudo ufw --force enable
  sleep 5
  sudo systemctl status ufw | sed -n "1,3p"
fi

print_color "32" "Done..."

# Install phpMyAdmin
print_color "36" "=> Installing phpMyAdmin:"
sleep 3

# Set debconf selections
debconf_selections=(
  "phpmyadmin phpmyadmin/reconfigure-webserver multiselect"
  "phpmyadmin phpmyadmin/dbconfig-install boolean true"
  "phpmyadmin phpmyadmin/mysql/admin-user string root"
  "phpmyadmin phpmyadmin/mysql/admin-pass password $rootpasswd"
  "phpmyadmin phpmyadmin/mysql/app-pass password $AUTOGENERATED_PASS"
  "phpmyadmin phpmyadmin/app-password-confirm password $AUTOGENERATED_PASS"
)

for selection in "${debconf_selections[@]}"; do
  echo "$selection" | sudo debconf-set-selections
done

# Install phpMyAdmin
sudo apt -y install phpmyadmin || displayErr "Failed to install phpMyAdmin."
sleep 5

print_color "32" "Done..."

# Installing Yiimp
print_color "36" "=> Installing Yiimp:"
sleep 3

# Generating Random Password for stratum
blckntifypass=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

# Clone and build Yiimp
cd ~
git clone https://github.com/nitrocon/yiimp-cryptoverse.eu.git || displayErr "Failed to clone Yiimp repository."
cd yiimp-cryptoverse.eu/blocknotify
sudo sed -i 's/tu8tu5/'"$blckntifypass"'/' blocknotify.cpp
make -j$(( $(nproc) + 1 )) || displayErr "Failed to build blocknotify."

# Compile Stratum
cd ../stratum
git submodule init && git submodule update || displayErr "Failed to initialize Stratum submodules."
make -C algos || displayErr "Failed to build Stratum algos."
make -C sha3 || displayErr "Failed to build Stratum sha3."
make -C iniparser || displayErr "Failed to build Stratum iniparser."
cd secp256k1 && chmod +x autogen.sh && ./autogen.sh && ./configure --enable-experimental --enable-module-ecdh --with-bignum=no --enable-endomorphism && make || displayErr "Failed to build Stratum secp256k1."
cd ..
if [[ "$BTC" == "y" || "$BTC" == "Y" ]]; then
  sudo sed -i 's/CFLAGS += -DNO_EXCHANGE/#CFLAGS += -DNO_EXCHANGE/' Makefile
fi
make -j$(( $(nproc) + 1 )) || displayErr "Failed to build Stratum."

print_color "32" "Done..."

# Copy Files (Blocknotify, iniparser, Stratum)
cd $HOME/yiimp-cryptoverse.eu
sudo sed -i 's/AdminRights/AdminPanel/' $HOME/yiimp-cryptoverse.eu/web/yaamp/modules/site/SiteController.php
sudo cp -r $HOME/yiimp-cryptoverse.eu/web /var/
sudo mkdir -p /var/stratum
cd $HOME/yiimp-cryptoverse.eu/stratum
sudo cp -a config.sample/. /var/stratum/config
sudo cp -r stratum /var/stratum
sudo cp -r run.sh /var/stratum
cd $HOME/yiimp-cryptoverse.eu
sudo cp -r $HOME/yiimp-cryptoverse.eu/bin/. /bin/
sudo cp -r $HOME/yiimp-cryptoverse.eu/blocknotify/blocknotify /usr/bin/
sudo cp -r $HOME/yiimp-cryptoverse.eu/blocknotify/blocknotify /var/stratum/
sudo mkdir -p /etc/yiimp
sudo mkdir -p $HOME/backup/

# Fixing yiimp
sudo sed -i "s|ROOTDIR=/data/yiimp|ROOTDIR=/var|g" /bin/yiimp

# Fixing run.sh
sudo rm -r /var/stratum/config/run.sh
echo '
#!/bin/bash
ulimit -n 10240
ulimit -u 10240
cd /var/stratum
while true; do
  ./stratum /var/stratum/config/$1
  sleep 2
done
exec bash
' | sudo -E tee /var/stratum/config/run.sh >/dev/null 2>&1
sudo chmod +x /var/stratum/config/run.sh

print_color "32" "Done..."

# Update Timezone
print_color "36" "=> Update default timezone. $COL_RESET"
sleep 3

print_color "36" "Setting TimeZone to UTC..."
if [ ! -f /etc/timezone ]; then
  echo "Setting timezone to UTC."
  echo "Etc/UTC" | sudo tee /etc/timezone >/dev/null
  sudo systemctl restart rsyslog
fi
sudo systemctl status rsyslog | sed -n "1,3p"
echo
sleep 3
print_color "32" "Done..."

# Creating webserver initial config file
print_color "36" "=> Creating webserver initial config file $COL_RESET"
echo

# Adding user to group, creating dir structure, setting permissions
sudo mkdir -p /var/www/$server_name/html

if [[ "$sub_domain" =~ [Yy] ]]; then
  sleep 3
  sudo tee /etc/nginx/sites-available/$server_name.conf >/dev/null <<EOF
include /etc/nginx/blockuseragents.rules;

server {
  if (\$blockedagent) {
    return 403;
  }
  
  if (\$request_method !~ ^(GET|HEAD|POST)$) {
    return 444;
  }
  
  listen 80;
  listen [::]:80;
  server_name ${server_name};
  
  root "/var/www/${server_name}/html/web";
  index index.html index.htm index.php;
  charset utf-8;

  location / {
    try_files \$uri \$uri/ /index.php?\$args;
  }
  
  location @rewrite {
    rewrite ^/(.*)$ /index.php?r=\$1;
  }

  location = /favicon.ico { access_log off; log_not_found off; }
  location = /robots.txt  { access_log off; log_not_found off; }

  access_log /var/log/nginx/${server_name}.app-access.log;
  error_log /var/log/nginx/${server_name}.app-error.log;

  # allow larger file uploads and longer script runtimes
  client_max_body_size 50k;
  sendfile off;

  location ~ ^/index\.php$ {
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    try_files \$uri \$uri/ =404;
  }
  
  location ~ \.php$ {
    return 404;
  }
  
  location ~ \.sh {
    return 404;
  }
  
  location ~ /\.ht {
    deny all;
  }
  
  location ~ /.well-known {
    allow all;
  }
  
  location ^~ /list-algos/ {
    deny all;
    access_log off;
    return 301 https://\$server_name;
  }
  
  location /phpmyadmin {
    root /usr/share/;
    index index.php;
    try_files \$uri \$uri/ =404;
    
    location ~ ^/phpmyadmin/(doc|sql|setup)/ {
      deny all;
    }
    
    location ~ /phpmyadmin/(.+\.php)$ {
      fastcgi_pass unix:/run/php/php7.3-fpm.sock;
      include fastcgi_params;
      fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
  }
}
EOF

  sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
  sudo ln -s /var/web /var/www/$server_name/html
  sudo ln -s /var/stratum/config /var/web/list-algos
fi

sudo systemctl reload php7.3-fpm.service
sudo systemctl restart nginx.service
print_color "32" "Done..."

if [[ ("$ssl_install" == "y" || "$ssl_install" == "Y" || "$ssl_install" == "") ]]; then

# Install SSL (with SubDomain)
echo
print_color "36" "Install LetsEncrypt and setting SSL (with SubDomain)"
echo

sudo add-apt-repository ppa:certbot/certbot
sudo add-apt-repository universe
sudo apt-get install -y certbot python-certbot-nginx
sudo certbot --nginx

# I am SSL Man!
ssl_config='
include /etc/nginx/blockuseragents.rules;

server {
  if ($blockedagent) {
    return 403;
  }
  
  if ($request_method !~ ^(GET|HEAD|POST)$) {
    return 444;
  }
  
  listen 80;
  listen [::]:80;
  server_name '"${server_name}"';
  
  # enforce https
  return 301 https://$server_name$request_uri;
}

server {
  if ($blockedagent) {
    return 403;
  }
  
  if ($request_method !~ ^(GET|HEAD|POST)$) {
    return 444;
  }
  
  listen 443 ssl http2;
  listen [::]:443 ssl http2;
  server_name '"${server_name}"';

  root /var/www/'"${server_name}"'/html/web;
  index index.php;

  access_log /var/log/nginx/'"${server_name}"'.app-access.log;
  error_log  /var/log/nginx/'"${server_name}"'.app-error.log;

  # allow larger file uploads and longer script runtimes
  client_body_buffer_size 50k;
  client_header_buffer_size 50k;
  client_max_body_size 50k;
  large_client_header_buffers 2 50k;
  sendfile off;

  # strengthen ssl security
  ssl_certificate /etc/letsencrypt/live/'"${server_name}"'/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/'"${server_name}"'/privkey.pem;
  ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
  ssl_prefer_server_ciphers on;
  ssl_session_cache shared:SSL:10m;
  ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:ECDHE-RSA-AES128-GCM-SHA256:AES256+EECDH:DHE-RSA-AES128-GCM-SHA256:AES256+EDH:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES128-SHA256:DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES256-GCM-SHA384:AES128-GCM-SHA256:AES256-SHA256:AES128-SHA256:AES256-SHA:AES128-SHA:DES-CBC3-SHA:HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4";
  ssl_dhparam /etc/ssl/certs/dhparam.pem;

  # Add headers to serve security related headers
  add_header Strict-Transport-Security "max-age=15768000; preload;";
  add_header X-Content-Type-Options nosniff;
  add_header X-XSS-Protection "1; mode=block";
  add_header X-Robots-Tag none;
  add_header Content-Security-Policy "frame-ancestors 'self'";

  location / {
    try_files $uri $uri/ /index.php?$args;
  }
  
  location @rewrite {
    rewrite ^/(.*)$ /index.php?r=$1;
  }

  location ~ ^/index\.php$ {
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_pass unix:/var/run/php/php7.3-fpm.sock;
    fastcgi_index index.php;
    include fastcgi_params;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_intercept_errors off;
    fastcgi_buffer_size 16k;
    fastcgi_buffers 4 16k;
    fastcgi_connect_timeout 300;
    fastcgi_send_timeout 300;
    fastcgi_read_timeout 300;
    include /etc/nginx/fastcgi_params;
    try_files $uri $uri/ =404;
  }
  
  location ~ \.php$ {
    return 404;
  }
  
  location ~ \.sh {
    return 404;
  }
  
  location ~ /\.ht {
    deny all;
  }
  
  location /phpmyadmin {
    root /usr/share/;
    index index.php;
    try_files $uri $uri/ =404;
    
    location ~ ^/phpmyadmin/(doc|sql|setup)/ {
      deny all;
    }
    
    location ~ /phpmyadmin/(.+\.php)$ {
      fastcgi_pass unix:/run/php/php7.3-fpm.sock;
      fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
      include fastcgi_params;
      include snippets/fastcgi-php.conf;
    }
  }
}
'

if [[ "$sub_domain" =~ [Yy] ]]; then
  sleep 3
  echo "$ssl_config" | sudo -E tee /etc/nginx/sites-available/$server_name.conf >/dev/null 2>&1
  sudo ln -s /etc/nginx/sites-available/$server_name.conf /etc/nginx/sites-enabled/$server_name.conf
  sudo ln -s /var/web /var/www/$server_name/html
  sudo ln -s /var/stratum/config /var/web/list-algos
fi

sudo systemctl reload "php${php_version}-fpm.service"
sudo systemctl restart nginx.service
print_color "32" "Done..."
