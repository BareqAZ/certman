#!/usr/bin/env bash
#
# Certman - Certificate Manager
# A script that automates OpenSSL certificates management; it can handle certificate issuance,
# revocation, and validation, as it provides both OCSP and CRL responders. 
#
#
# Requierments:
# - OpenSSL > 1.1.1k
# - Nginx (optional)
# - Redhat 7/8 based distribution


# Key variables
# Installation directory
DIR="$HOME/.config/certman"

# Authority
ROOT_SIZE=4096
ROOT_VALIDITY=1825
INTERMEDIATE_SIZE=2048
INTERMEDIATE_VALIDITY=365

# Signed/Generated keys
CERT_SIZE=2048
CERT_VALIDITY=365

# Root certificate information
ROOT_C="US"
ROOT_ST="California"
ROOT_L="San Francisco"
ROOT_O="Internal Lab"
ROOT_OU="Internal lab root CA"
ROOT_CN="Internal lab root CA"
ROOT_EMAIL="admin@lab.local"

# Intermediate certificate information
CA_C="US"
CA_ST="California"
CA_L="San Francisco"
CA_O="Internal Lab"
CA_OU="Internal lab CA"
CA_CN="Internal lab CA"
CA_EMAIL="admin@lab.local"

# CSRs and Generated certificates
CERT_C="US"
CERT_ST="California"
CERT_L="San Francisco"
CERT_O="Internal Lab"
CERT_OU="Internal lab"
CERT_CN="Internal lab"

# CRL and OCSP settings.
# Need to reinstall each service in order for these to take effect.
CRL_PORT=80
CRL_interval=60
OCSP_PORT=443


# Arguments parsing
while [ $# -gt 0 ]; do
    case $1 in
        -s  | --sign)
             [[ ! -f $2 ]] && { printf "This option requires a file!\n"; exit 1; }
             SIGN=$2
             break 2;;
        -g  |  --generate)
             GEN=true
             break 2;;
        -h  | --help)
             HELP=true
             break 2;;
        -l  | --list)
             LIST=true
             ARG=$2
             break 2;;
        -r  | --revoke)
             REV=true
             ARG=$2
             break 2;;
        -st |--state)
             STATE=true
             break 2;;
        -in | --install)
            [[ -z $2 ]] && { printf "This argument requires one of the following options 'clean, crl, ocsp'.\n"; exit 1; }
             INSTALL=true
             break 2;;
        -im | --import)
             IMPORT=true
             break 2;;
        -un | --uninstall)
             UNINSTALL=true
             break 2;;
    esac
    shift
done

[[ -n $UNINSTALL ]] && {
    printf "Are you sure you want to uninstall Certman? [y/N]\n"
    read -p "==> "
    [[ ! $REPLY =~ (y|Y) ]] && { printf "Exiting...\n"; exit 0; }
    printf "Would you like to backup your certificates and DB? [Y/n]\n"
    read -p "==> "
    [[ ! $REPLY =~ (n|N) ]] && tar -czvf $PWD/certman.tar.gz $DIR

    rm -rf $DIR
    systemctl disable certman-crl
    systemctl stop certman-crl
    rm -f /lib/systemd/system/certman-crl.service
    systemctl disable certman-ocsp
    systemctl stop certman-ocsp
    rm -f /lib/systemd/system/certman-ocsp.service
    sudo systemctl daemon-reload
    rm -f /bin/certman
    rm -rf /usr/share/nginx/crl 2>/dev/null

which nginx >/dev/null 2>&1 && {
printf "Uninstall Nginx? [Y/n]\n"
read -p "==> "
[[ ! $REPLY =~ (n|N) ]] && {
    [ -f /etc/redhat-release ] && sudo yum remove nginx -y
    [ -f /etc/arch-release   ] && sudo pacman -R nginx
    [ -f /etc/gentoo-release ] && sudo emerge -Cav app-shells/nginx -y
    [ -f /etc/SuSE-release   ] && sudo zypper remove nginx -y
    [ -f /etc/debian_version ] && sudo apt remove nginx -y
    [ -f /etc/alpine-release ] && sudo apk del nginx -y
    [ -f /etc/fedora-release ] && sudo dnf remove nginx -y
    }
  }
  exit 0
}


[[ -n $INSTALL ]] && {
while [ $# -gt 1 ]; do
    case $2 in
        clean)
        rm -rf $DIR
        shift
        continue;;
        crl)
        CRL_INSTALL="Y"
        shift
        continue;;
        ocsp)
        OCSP_INSTALL="Y"
        shift
        continue;;
esac
break
done
}


# Import an existing ROOT CA
[[ -n $IMPORT ]] && {
[[ -f $2 && -f $3 ]] && {
{ grep "PRIVATE" "$2" >/dev/null && ROOTCA_KEY=$(cat "$2") && grep "CERTIFICATE" "$3" >/dev/null && ROOTCA=$(cat "$3"); } || \
{ grep "PRIVATE" "$3" >/dev/null && ROOTCA_KEY=$(cat "$3") && grep "CERTIFICATE" "$2" >/dev/null && ROOTCA=$(cat "$2"); }
INSTALL_CERTMAN=true
} || { printf "Please select both ROOT CA and ROOT CA key\n"; exit 1; }; }


# Source the Certman configuration file
# Otherwise prompt for installation
[[ -z $IMPORT ]] && {
source $DIR/certman.conf 2>/dev/null ||  {
printf "It looks like certman is not installed.\nWould you like to install it ? [Y/n]\n"
    read -p "==> " INSTALL_CERTMAN
    [[  $INSTALL_CERTMAN =~ (n|N) ]] && { printf "Exiting...\n"; exit 0; }
  }
}


# Certman installation
[[ -n $INSTALL_CERTMAN ]] && {
SRC=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
# Check if certman has already been configured
[[ -f $DIR/certman.conf ]] && {
    printf "It seems like Certman has already been configured before!\n"
    printf "Would you like to remove your previous installation?. [y/N] \n"
    read -p "==> "
    [[ ! $REPLY =~ (y|Y) ]] && { printf "Exiting...\n"; exit 0; }
    rm -rf $DIR; }

# Start of ROOT CA installation
    trap "rm -rf $DIR; exit 1" INT
	CONF_C=$ROOT_C
	CONF_ST=$ROOT_ST
	CONF_L=$ROOT_L
	CONF_O=$ROOT_O
	CONF_OU=$ROOT_OU
	CONF_CN=$ROOT_CN
	CONF_EMAIL=$ROOT_EMAIL
    POLICY="policy_strict"
    source $SRC/certman.conf || {
        printf "ERROR: certman.conf not found!\nPlease make sure the file exist in the same directory before starting the installation.\n"
        exit 127; }
    umask 027
    mkdir -p $DIR; cd $DIR || exit 1
    mkdir certs crl newcerts private 2>/dev/null
    chmod 700 private
    touch index
    printf "unique_subject = no" > index.attr
    echo 1000 > serial
    cp $SRC/certman.conf $DIR/certman.conf
    source $DIR/certman.conf
    printf "$CONF" > rootca.conf

# If ROOTCA is null then generate new one
[[ -z $ROOTCA ]] && {
    while :; do
printf "Set password for your ROOT CA.\n[Default: No Password]\n"
        read -s -p "==> " PASS
        # Check if password matches and is longer than 3 characters.
        [[ -n $PASS ]] && {
            [[ ${#PASS} -le 3 ]] && printf "\nERROR: Password must be longer than 3 characters!\n" && continue
            printf "\nConfirm your password\n"
            read -s -p "==> "
            [[ ! $REPLY == $PASS ]] && printf "\nPassword doesn't match\n" && continue ;}
            break
        done

    [[ -n $PASS ]] && PO="-aes256 -passout pass:"$PASS"" ROOT_PW="-passin pass:"$PASS""

    # ROOT CA private key
    openssl genrsa $PO -out private/ROOTCA.key $ROOT_SIZE || exit 1
    chmod 400 private/ROOTCA.key

    # ROOT CA Certificate
    openssl req $ROOT_PW -new -x509 -days $ROOT_VALIDITY -sha256 -extensions v3_ca    \
                         -config rootca.conf                                \
                         -key private/ROOTCA.key                            \
                         -out certs/ROOTCA.pem || exit 1
    chmod 444 certs/ROOTCA.pem

} || {
# Use an existing ROOTCA
printf '%s\n' "${ROOTCA_KEY}"   > private/ROOTCA.key
    chmod 400 private/ROOTCA.key
printf '%s\n' "${ROOTCA}"       > certs/ROOTCA.pem
    chmod 444 certs/ROOTCA.pem
}


# Intermediate Certificate installation
printf "Generating the Certificate Authority...\n"
    mkdir ca 2>/dev/null; cd ca
    mkdir certs crl csr newcerts private confs services scripts 2>/dev/null
    chmod 700 private
    touch index
    printf "unique_subject = no" > index.attr
    echo 1000 > serial
    echo 1000 > crlnumber

	CONF_C=$CA_C
	CONF_ST=$CA_ST
	CONF_L=$CA_L
	CONF_O=$CA_O
	CONF_OU=$CA_OU
	CONF_CN=$CA_CN
	CONF_EMAIL=$CA_EMAIL
    POLICY="policy_loose"
source $DIR/certman.conf
printf "$CONF" > ca.conf
    sed -i -e "s/.config\/certman/.config\/certman\/ca/" ca.conf
    sed -i -e "s/ROOTCA.key/ca.key/" ca.conf
    sed -i -e "s/ROOTCA.pem/ca.pem/" ca.conf
    sed -i -e "s/ROOTCA.crl.pem/ca.crl.pem/" ca.conf
    sed -i -e "s/= policy_strict/= policy_loose/" ca.conf

    # Generating Intermediate CA key
    openssl genrsa -out private/ca.key $INTERMEDIATE_SIZE || exit 1
    chmod 400 private/ca.key

    # Generating Intermediate CA CSR
    openssl req -config ca.conf       \
                -new -sha256          \
                -key private/ca.key   \
                -out csr/ca.csr

    # Signing Intermediate CA
    cd ..
    openssl ca  -extensions v3_intermediate_ca -days $INTERMEDIATE_VALIDITY -notext -md sha256 -batch \
                -config rootca.conf                                                 \
                -in ca/csr/ca.csr                                                   \
                -out ca/certs/ca.pem                                                \
                $ROOT_PW

    chmod 444 ca/certs/ca.pem

    # Creating CA chain
    cat ca/certs/ca.pem certs/ROOTCA.pem > ca/certs/ca-chain.pem

    chmod 444 ca/certs/ca-chain.pem
    openssl verify -CAfile certs/ROOTCA.pem ca/certs/ca.pem || exit 1

# Prompt for CRL server installation
[[ -z $CRL_INSTALL ]] && printf "Install a CRL server ? [y/N]\n" && \
read -p "==> " CRL_INSTALL

# Prompt for OCSP server installation
[[ -z $OCSP_INSTALL ]] && printf "Install an OCSP server ? [y/N]\n" && \
read -p "==> " OCSP_INSTALL

sudo cp $SRC/certman.sh /bin/certman
sudo chmod 755 /bin/certman

# Call for installation end screen
INSTALL_END=norm
}

# CRL Server installation
[[ $CRL_INSTALL =~ (y|Y) ]] && {
    PW=""
cd $DIR/ca
    printf "Enter FQDN for the new CRL/OCSP server:\n"
    printf "Don't use 'https://' or 'www.'\n"
    while :; do
    read -p "==> "
    [[  $REPLY =~ \w*\.\w* ]] && \
        FQDN=$REPLY && \
        break 1
        printf "Please enter a valid FQDN!\n"
    done
source $DIR/certman.conf
# Check and install dependencies
which nginx >/dev/null 2>&1 || {
printf "Nginx is not found, will attempt to install it!\n"

    [ -f /etc/redhat-release ] && sudo yum install nginx -y
    [ -f /etc/arch-release   ] && sudo pacman -S nginx
    [ -f /etc/gentoo-release ] && sudo emerge app-shells/nginx -y
    [ -f /etc/SuSE-release   ] && sudo zypper install nginx -y
    [ -f /etc/debian_version ] && sudo apt install nginx -y
    [ -f /etc/alpine-release ] && sudo apk add nginx -y
    [ -f /etc/fedora-release ] && sudo dnf install nginx -y
}

# Start CRL server installation
printf "Updating configuration files..\n"
    sed -i -E "s/#?crlDistributionPoints.*$/crlDistributionPoints = URI:http:\/\/$FQDN:$CRL_PORT\/check.crl/" ca.conf         &&
    sed -i -E "s/#?crlDistributionPoints.*$/crlDistributionPoints = URI:http:\/\/$FQDN:$CRL_PORT\/check.crl/" ../certman.conf || {
        printf "Failed updating certificate authority configuration file!\n"; exit 1; }

printf "Testing generating CRL...\n"
openssl ca -config ca.conf -gencrl \
        -out crl/check.crl || {
        printf "ERROR: could not generate CRL!\n"
        exit 1; }


# Configuring Nginx
printf "Configuring Nginx...\n"
sudo printf "$NGINX_CONFIG" > /etc/nginx/nginx.conf &&
mkdir -p /var/www/crl                               &&
touch /var/www/crl/check.crl                        || {
     printf "ERROR: unable to install nginx configuration!\n"; exit 1; }

# Configuring CRL reload script
printf "Configuring CRL reload script...\n"
source $DIR/certman.conf
printf "$CRL_RELOAD" > scripts/crl_reload                                && \
chmod 700 scripts/crl_reload                                             && \
sudo printf "$CRL_SYSTEMD" > /lib/systemd/system/certman-crl.service     && \
sudo systemctl daemon-reload                                             && \
sudo systemctl enable certman-crl                                        && \

# Checking for SELinux
printf "Checking for SELinux\n"                                          && \
 getenforce >/dev/null 2>&1 && {
    printf "SELinux is found, setting context...\n"
    # Scripts
    sudo chcon -Rv -u system_u -t bin_t "$DIR/ca/scripts/"
    sudo semanage fcontext -a -t bin_t "$DIR/ca/scripts/crl_reload"
    sudo restorecon -R -v "$DIR/ca/scripts/"
    # Nginx
    sudo restorecon -RFvv "/var/www/crl/"
} || printf "SELinux not found, skipping setting context.\n"
printf "Reloading Nginx...\n"
sudo nginx -s reload
printf "Starting certman-crl service...\n"
sudo systemctl restart certman-crl || exit 1
sudo systemctl is-active certman-crl >/dev/null || {
    printf "certman-crl has failed to start!\nAborting...\n"; exit 1; }
printf "certman-crl service is started.\n"

which firewall-cmd >/dev/null 2>&1 && {
    printf "Configuring firewalld...\n"
    sudo firewall-cmd --permanent --add-port=$CRL_PORT/tcp
    sudo firewall-cmd --reload; }
}


# OCSP Server installation
[[ $OCSP_INSTALL =~ (y|Y) ]] && {
cd $DIR/ca
    [[ -z $FQDN ]] && {
    printf "Enter FQDN for the new CRL/OCSP server:\n"
    printf "Don't use 'https://' or 'www.'\n"
    while :; do
    read -p "==> "
    [[  $REPLY =~ \w*\.\w* ]] && \
        FQDN=$REPLY && \
        break 1
        printf "Please enter a valid FQDN!\n"
    done
    }


source $DIR/certman.conf

FQDN="ocsp.$FQDN"
printf "Updating configuration files..\n"
    sed -i -E "s/#?authorityInfoAccess.*$/authorityInfoAccess = OCSP;URI:http:\/\/$FQDN:$OCSP_PORT/" ca.conf           &&
    sed -i -E "s/#?authorityInfoAccess.*$/authorityInfoAccess = OCSP;URI:http:\/\/$FQDN:$OCSP_PORT/" ../certman.conf   || {
        printf "Failed updating certificate authority configuration file!\n"; exit 1; }

printf "Configuring OCSP server...\n"
printf "$OCSP_SCRIPT" > scripts/ocsp                                      && \
chmod 700 scripts/ocsp                                                    && \
sudo printf "$OCSP_SYSTEMD" > /lib/systemd/system/certman-ocsp.service    && \
sudo systemctl daemon-reload                                              && \
sudo systemctl enable certman-ocsp                                        && \

# Checking for SELinux
printf "Checking for SELinux\n"                                           && \
 getenforce >/dev/null 2>&1 && {
    printf "SELinux is found, setting context...\n"
    sudo chcon -Rv -u system_u -t bin_t "$DIR/ca/scripts/"
    sudo semanage fcontext -a -t bin_t "$DIR/ca/scripts/ocsp"
    sudo restorecon -R -v "$DIR/ca/scripts/"
} || printf "SELinux not found, skipping setting context.\n"
printf "Starting certman-ocsp service...\n"
sudo systemctl restart certman-ocsp || exit 1
sudo systemctl is-active certman-ocsp >/dev/null || {
    printf "certman-ocsp has failed to start!\nAborting...\n"; exit 1; }
printf "certman-ocsp service is started.\n"

which firewall-cmd >/dev/null 2>&1 && {
    printf "Configuring firewalld...\n"
    sudo firewall-cmd --permanent --add-port=$OCSP_PORT/tcp
    sudo firewall-cmd --reload; }
}


# Installation successful message
[[ $INSTALL_END == "norm" ]] && {
cat <<EOF
The Certificate Authority has been established.
################################################
ROOT CA         : $DIR/certs/ROOTCA.pem
ROOT CA key     : $DIR/private/ROOTCA.key
Intermediate    : $DIR/ca/certs/ca.pem
Intermediate key: $DIR/ca/private/ca.key
CA Chain        : $DIR/ca/certs/ca-chain.pem
################################################

To start using your Certificate Authority:
 - Install the CA chain to whichever client you want to trust the Certificates signed by this CA.
 - Generate a new certificate with "certman -g"
 - Sign an existing CSR with "certman -s file.csr"
 - Monitor your certificates with "certman -l -a"

For the full instructions please check the help page. "certman --help"
EOF
exit 0
}

# Automatically create key, csr and new certificate
[[ -n $GEN ]] && {
    cd $DIR/ca

while [ $# -gt 1 ]; do
    case $2 in
        -f)
        OUTPUT_FILE=$3
        shift 2
        continue;;

        *)
        [[ $2 =~ \w*\.\w* ]] && \
            FQDN=$2          || \
            printf "Incorrect FQDN format!\n"
        shift
        continue;;
esac
break
done

    # Check FQDN
    [[ -z $FQDN ]] && {
    printf "Enter FQDN for the new certificate:\n"
    printf "Don't use 'https://' or 'www.'\n"
    while :; do
    read -p "==> "
    [[  $REPLY =~ \w*\.\w* ]] && \
        FQDN=$REPLY && \
        break 1
        printf "Please enter a valid FQDN!\n"
    done
    }

    # Generate a new key
    while :; do
printf "Set password for your new certificate.\n[Default: No Password]\n"
        read -s -p "==> " PASS
        # Check if password matches and is longer than 3 characters.
        [[ -n $PASS ]] && {
            [[ ${#PASS} -le 3 ]] && printf "\nERROR: Password must be longer than 3 characters!\n" && continue
            printf "\nConfirm your password\n"
            read -s -p "==> "
            [[ ! $REPLY == $PASS ]] && printf "\nPassword doesn't match\n" && continue ;}
            break
        done
        PO=""
    [[ -n $PASS ]] && PO="-aes256 -passout pass:"$PASS"" PW="-passin pass:"$PASS""

    # Generate a key
    openssl genrsa $PO -out private/$FQDN.key $CERT_SIZE || exit 1
    chmod 400 private/$FQDN.key

source $DIR/certman.conf
printf "$CSR" > confs/$FQDN.conf
printf "$EXT" > confs/$FQDN.ext

    # Generate a csr
    openssl req -config confs/$FQDN.conf -batch   \
                -key private/$FQDN.key            \
                -new -sha256 -out csr/$FQDN.csr  || exit 1

    # Generate a certificate
    openssl ca  -config ca.conf -days $CERT_VALIDITY -notext -md sha256 -batch  \
                -extfile confs/$FQDN.ext                                        \
                -in csr/$FQDN.csr                                               \
                -out certs/$FQDN.pem || exit 1
    chmod 444 certs/$FQDN.pem

    # Verify the certificate
    openssl verify -CAfile certs/ca-chain.pem certs/$FQDN.pem || exit 1
    cd
    [[ -n $OUTPUT_FILE ]] && cat $DIR/ca/certs/$FQDN.pem > "$OUTPUT_FILE.pem"
    [[ -n $OUTPUT_FILE ]] && cat $DIR/ca/private/$FQDN.key > "$OUTPUT_FILE.key"

cat << EOF
##############################################################################
Certificate has been generated successfully.
Cert        : $DIR/ca/certs/$FQDN.pem
Cert key    : $DIR/ca/private/$FQDN.key
CA Chain    : $DIR/ca/certs/ca-chain.pem
##############################################################################
EOF

}

# Sign an existing csr
[[ -n $SIGN ]] && {
OUT=$(printf $SIGN | sed -e 's/.csr/.pem/')

    # Get the FQDN
    FQDN=$(openssl req -noout -subject -in $SIGN | grep -oP '(?<=CN\s=\s).*') || {
        printf "ERROR: Failed to find the FQDN in the csr!"
        exit 1;}

    # Generate extfile
    source $DIR/certman.conf
    printf "$EXT" > $DIR/ca/confs/$FQDN.ext

    # Generate a certificate
    openssl ca  -config $DIR/ca/ca.conf -days $CERT_VALIDITY -notext -md sha256 -batch  \
                -extfile $DIR/ca/confs/$FQDN.ext                                        \
                -in $SIGN                                                               \
                -out $DIR/ca/certs/$FQDN.pem || exit 1
    chmod 444 $DIR/ca/certs/$FQDN.pem
    cp -a $DIR/ca/certs/$FQDN.pem $OUT

    # Verify the certificate
    openssl verify -CAfile $DIR/ca/certs/ca-chain.pem $OUT || exit 1

printf "Certificate has been signed successfully.\n"
}


# List certificates from index
[[ -n $LIST ]] && {
cd $DIR/ca
LIST_FILTER="^V"
[[ $ARG == "-a" ]] && LIST_FILTER=""

IFS=$'\n'
printf " ID     Name                     Issued                     Expires                    Status\n"
printf " ====== ======================== ========================== ========================== =========\n"
for CERT in $(tac index | grep "$LIST_FILTER" | head -n 25)
do
    N=$(awk '{ if ($1 ~ "V") print $3; else print $4}' <<< "$CERT")
    ISSUED=$(openssl x509 -startdate -noout -in newcerts/$N.pem | sed -e "s/notBefore=//")
    EXPIRES=$(openssl x509 -enddate -noout -in newcerts/$N.pem | sed -e "s/notAfter=//")
    STATUS=$(awk '{printf $1}' <<< $CERT | sed 's/V/\\e[32mActive\\e[0m/;s/R/\\e[31mRevoked\\e[0m/;s/E/\\e[33mExpired\\e[0m/')
    FQDN=$(printf $CERT | grep -oP "CN=.*$" | sed "s/CN=\*\.//;s/CN=//")
    printf "| %-4s | %-22s | %-24s | %-24s | "$STATUS" \n" "$N" "$FQDN" "$ISSUED" "$EXPIRES"
done
printf " ====== ======================== ========================== ========================== =========\n"
}


# Revoke certificate
[[ -n $REV ]] && {
cd $DIR/ca

# Revoke certificate by FQDN
[[ $ARG =~ \w*\.\w*  ]] && {
    CERT_ID=$(grep -P "^V" index | grep -P "$ARG" | awk '{print $3}')
} || CERT_ID=$ARG

# Revoke certificate by ID
[[ ! -f "newcerts/$CERT_ID.pem" ]] && { printf "ERROR: Certificate not found!\n"; exit 1;}
openssl ca -config ca.conf -revoke newcerts/$CERT_ID.pem || exit 1
printf "Certificate ID:$CERT_ID has been revoked successfully.\n"
}

[[ -n $STATE ]] && {
CRL_STATUS=$(systemctl is-active certman-crl 2>/dev/null | sed -e 's/^active/\\e[32mActive\\e[0m/;s/failed/\\e[31mFailed\\e[0m/')
OCSP_STATUS=$(systemctl is-active certman-ocsp 2>/dev/null | sed -e 's/^active/\\e[32mActive\\e[0m/;s/failed/\\e[31mFailed\\e[0m/')
systemctl status certman-crl 2>/dev/null >/dev/null; [[ $? == 4 ]] && CRL_STATUS="\\e[33mNot Installed\\e[0m"
systemctl status certman-ocsp 2>/dev/null >/dev/null; [[ $? == 4 ]] && OCSP_STATUS="\\e[33mNot Installed\\e[0m"
    printf " Service\tStatus\n ==============\t========\n"
    printf " Certman CRL\t$CRL_STATUS\t\n"
    printf " Certman OCSP\t$OCSP_STATUS\t\n"
    printf " ==============\t========\n"
}

[[ $# -eq 0 ]] || [[ -n $HELP ]] &&
printf "Certman - Certificate Manager

\e[1;33mUsage:\e[0m

    \e[1;32m-in | --Install\e[0m     Requires one of the following options 'clean, crl, ocsp'.
    \e[1;32m-in clean\e[0m           Remove the previous installation and prompt for a fresh install.
    \e[1;32m-in crl\e[0m             Install and configure CRL server.
    \e[1;32m-in ocsp\e[0m            Install and configure OCSP responder.

    \e[1;32m-un | --uninstall\e[0m   Uninstall and clean up all the changes made by installing Certman.

    \e[1;32m-im | --import\e[0m      Import an existing Certificate as ROOT CA instead of generating a new one.
                        Requires A certificate file and A certificate key file.
                        Example: --import myca.pem myca.key

    \e[1;32m-st | --state\e[0m       Check the status of OCSP and CRL services.

    \e[1;32m-g  | --generate\e[0m    Generate a key and a signed Certificate.
    \e[1;32m-g test.domain\e[0m      Use the FQDN 'test.domain' instead of prompting for FQDN.
    \e[1;32m-g -f file\e[0m          Output the Key and Certificate to 'file.key' and 'file.pem'.

    \e[1;32m-s  | --sign\e[0m        Sign an existing csr.

    \e[1;32m-r  | --revoke\e[0m      Revoke a certificate.

    \e[1;32m-l  | --list\e[0m        List valid certificates.

    \e[1;32m-l -a\e[0m               List all certificates.

"
