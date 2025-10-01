#!/bin/bash

# Phishing Test Altyapısı Otomatik Kurulum Scripti
# Kullanım: ./setup.sh -d domain.com -i SERVER_IP

set -e

# Renkli output için
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parametreleri parse et
while getopts "d:i:h" opt; do
    case $opt in
        d) DOMAIN="$OPTARG" ;;
        i) SERVER_IP="$OPTARG" ;;
        h) 
            echo "Kullanım: $0 -d domain.com -i SERVER_IP"
            echo "  -d: Domain adı (örn: test-domain.com)"
            echo "  -i: Sunucu IP adresi"
            exit 0
            ;;
        \?) 
            log_error "Geçersiz parametre. -h ile yardımı görüntüleyin."
            exit 1
            ;;
    esac
done

# Parametreleri kontrol et
if [ -z "$DOMAIN" ] || [ -z "$SERVER_IP" ]; then
    log_error "Domain (-d) ve IP (-i) parametreleri zorunludur!"
    echo "Kullanım: $0 -d domain.com -i SERVER_IP"
    exit 1
fi

log_info "Kurulum başlıyor..."
log_info "Domain: $DOMAIN"
log_info "Server IP: $SERVER_IP"

# SSH'yi etkinleştir
log_info "SSH servisi etkinleştiriliyor..."
systemctl enable ssh
systemctl start ssh

# Sistem güncellemesi ve Postfix kurulumu
log_info "Sistem güncelleniyor ve Postfix kuruluyor..."
DEBIAN_FRONTEND=noninteractive apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get install -y postfix mailutils

# Postfix'i Internet Site olarak yapılandır
log_info "Postfix yapılandırılıyor..."
debconf-set-selections <<< "postfix postfix/mailname string $DOMAIN"
debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

# Hostname ayarla
log_info "Hostname ayarlanıyor..."
echo "$DOMAIN" > /etc/hostname
hostname "$DOMAIN"

# Postfix main.cf düzenle
log_info "Postfix main.cf düzenleniyor..."
sed -i "s/^myhostname =.*/myhostname = $DOMAIN/" /etc/postfix/main.cf

# /etc/hosts düzenle
log_info "/etc/hosts düzenleniyor..."
sed -i "s/^127.0.0.1.*/127.0.0.1 localhost/" /etc/hosts
echo "$SERVER_IP $DOMAIN" >> /etc/hosts

# Mailname ayarla
log_info "Mailname ayarlanıyor..."
echo "$DOMAIN" > /etc/mailname

# OpenDKIM kurulumu
log_info "OpenDKIM kuruluyor..."
apt-get install -y opendkim opendkim-tools

# Postfix kullanıcısını opendkim grubuna ekle
gpasswd -a postfix opendkim

# OpenDKIM yapılandırma
log_info "OpenDKIM yapılandırılıyor..."
cat > /etc/opendkim.conf << EOF
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   002
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes

Canonicalization        relaxed/simple

ExternalIgnoreList      refile:/etc/opendkim/trusted.hosts
InternalHosts           refile:/etc/opendkim/trusted.hosts
KeyTable                refile:/etc/opendkim/key.table
SigningTable            refile:/etc/opendkim/signing.table

Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256

UserID                  opendkim:opendkim

Socket                  local:/var/spool/postfix/opendkim/opendkim.sock
EOF

# OpenDKIM dizinlerini oluştur
log_info "OpenDKIM dizinleri oluşturuluyor..."
mkdir -p /etc/opendkim/keys
chown -R opendkim:opendkim /etc/opendkim
chmod go-rw /etc/opendkim/keys

# Signing table
log_info "OpenDKIM signing table oluşturuluyor..."
cat > /etc/opendkim/signing.table << EOF
*@$DOMAIN default._domainkey.$DOMAIN
*@*.$DOMAIN default._domainkey.$DOMAIN
EOF

# Key table
log_info "OpenDKIM key table oluşturuluyor..."
cat > /etc/opendkim/key.table << EOF
default._domainkey.$DOMAIN $DOMAIN:default:/etc/opendkim/keys/$DOMAIN/default.private
EOF

# Trusted hosts
log_info "OpenDKIM trusted hosts oluşturuluyor..."
cat > /etc/opendkim/trusted.hosts << EOF
127.0.0.1
localhost

*.$DOMAIN
EOF

# DKIM anahtarları oluştur
log_info "DKIM anahtarları oluşturuluyor..."
mkdir -p /etc/opendkim/keys/$DOMAIN
opendkim-genkey -b 2048 -d $DOMAIN -D /etc/opendkim/keys/$DOMAIN -s default -v
chown opendkim:opendkim /etc/opendkim/keys/$DOMAIN/default.private
chmod 600 /etc/opendkim/keys/$DOMAIN/default.private

# DKIM public key'i göster
log_info "DKIM Public Key (DNS'e eklenecek):"
echo "=================================================="
cat /etc/opendkim/keys/$DOMAIN/default.txt | tr -d '\n' | sed 's/[[:space:]]\+/ /g' | sed 's/" "//g' | sed 's/[()]//g'
echo ""
echo "=================================================="

# OpenDKIM socket dizini
log_info "OpenDKIM socket dizini oluşturuluyor..."
mkdir -p /var/spool/postfix/opendkim
chown opendkim:postfix /var/spool/postfix/opendkim

# OpenDKIM default ayarları
log_info "OpenDKIM default ayarları yapılandırılıyor..."
cat > /etc/default/opendkim << EOF
SOCKET="local:/var/spool/postfix/opendkim/opendkim.sock"
EOF

# Postfix'e milter ekle
log_info "Postfix'e OpenDKIM milter ekleniyor..."
cat >> /etc/postfix/main.cf << EOF

# OpenDKIM milter configuration
milter_default_action = accept
milter_protocol = 6
smtpd_milters = local:opendkim/opendkim.sock
non_smtpd_milters = \$smtpd_milters
EOF

# Servisleri yeniden başlat
log_info "Postfix ve OpenDKIM yeniden başlatılıyor..."
systemctl restart opendkim
systemctl restart postfix
systemctl enable postfix
systemctl enable opendkim

# DKIM test
log_info "DKIM anahtarı test ediliyor..."
sleep 2
opendkim-testkey -d $DOMAIN -s default -vvv || log_warn "DKIM testi başarısız. DNS kayıtlarını kontrol edin."

# Gophish kurulumu
log_info "Gophish indiriliyor..."
cd /root
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip -O gophish.zip
apt-get install -y unzip
unzip -o gophish.zip
chmod +x gophish

# Gophish config.json düzenle
log_info "Gophish yapılandırılıyor..."
cat > config.json << EOF
{
	"admin_server": {
		"listen_url": "0.0.0.0:3333",
		"use_tls": true,
		"cert_path": "gophish_admin.crt",
		"key_path": "gophish_admin.key",
		"trusted_origins": []
	},
	"phish_server": {
		"listen_url": "0.0.0.0:91",
		"use_tls": false,
		"cert_path": "example.crt",
		"key_path": "example.key"
	},
	"db_name": "sqlite3",
	"db_path": "gophish.db",
	"migrations_prefix": "db/db_",
	"contact_address": "",
	"logging": {
		"filename": "",
		"level": ""
	}
}
EOF

# Gophish systemd servisi
log_info "Gophish systemd servisi oluşturuluyor..."
cat > /etc/systemd/system/gophish.service << EOF
[Unit]
Description=gophish-service

[Service]
Type=simple
WorkingDirectory=/root
ExecStart=/root/gophish

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start gophish.service
systemctl enable gophish.service

# Nginx kurulumu
log_info "Nginx kuruluyor..."
apt-get install -y nginx

# Nginx yapılandırması
log_info "Nginx yapılandırılıyor..."
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/default

cat > /etc/nginx/conf.d/$DOMAIN.conf << EOF
server {
    server_name $DOMAIN www.$DOMAIN *.$DOMAIN;
    client_max_body_size 75M;
    
    add_header 'Access-Control-Allow-Origin' '*';
    add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
    
    access_log /var/log/nginx/$DOMAIN.log;
    
    location /error.html {
        root /var/www/html;
        index error.html;
    }
    
    location / {
        include proxy_params;
        proxy_pass http://127.0.0.1:91;
        proxy_buffering off;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port \$server_port;
    }
    
    listen 80;
}
EOF

# Nginx test ve başlat
log_info "Nginx test ediliyor..."
nginx -t
systemctl restart nginx
systemctl enable nginx

# Certbot kurulumu
log_info "Certbot kuruluyor..."
apt-get install -y certbot python3-certbot-nginx

log_info "============================================"
log_info "Kurulum tamamlandı!"
log_info "============================================"
log_info ""
log_info "YAPILMASI GEREKENLER:"
log_info ""
log_info "1. DNS Kayıtları (Cloudflare'de oluşturun):"
log_info "   - A kaydı: @ -> $SERVER_IP"
log_info "   - MX kaydı: @ -> $DOMAIN (Priority: 10)"
log_info "   - SPF kaydı: TXT @ -> v=spf1 mx ~all"
log_info "   - DKIM kaydı: Yukarıda gösterilen public key'i TXT olarak ekleyin"
log_info "   - DMARC kaydı: TXT _dmarc -> v=DMARC1; p=none; rua=mailto:dmarc@$DOMAIN"
log_info ""
log_info "2. SSL Sertifikası (DNS kayıtları yayıldıktan sonra):"
log_info "   certbot --nginx -d $DOMAIN"
log_info ""
log_info "3. Reverse DNS (Contabo'da):"
log_info "   $SERVER_IP -> $DOMAIN"
log_info ""
log_info "4. Gophish Admin Panel:"
log_info "   https://$DOMAIN:3333"
log_info "   (İlk giriş bilgileri /root/gophish klasöründe)"
log_info ""
log_info "5. Servis durumları:"
log_info "   systemctl status postfix"
log_info "   systemctl status opendkim"
log_info "   systemctl status gophish"
log_info "   systemctl status nginx"
log_info ""
log_info "Test mail gönderme:"
log_info "echo \"test mail\" | mailx -s \"test subject\" -r test@$DOMAIN hedef@mail.com"
log_info ""
log_info "============================================"
