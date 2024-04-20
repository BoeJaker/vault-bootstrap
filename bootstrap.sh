#!/bin/bash

: '
use a .env file in the same direcotry with the following environment variables:
VAULT_ADDR="" # Required, address of the vault server
VAULT_TOKEN="" # Required, an admin token to your hashicorp vault
USER="" # Optional, if nothing is specified a psudorandom name will be generated
PASS="" # Optional, if nothing is specified a random password will be generated


Generates an authentication method for vault for the parent container.
Creates a psudorandom user and random password for the container and shares with vault.
Generatees a database user for the container via vault.
Generates TLS certificates and a PGP key pair for the container to use, also dhared with vault.
Pulls any third party variables like API Keys from vault.
All generated credentials will be stored under the hostname of the container.

To Do:
database init:
inits a database user

Init, 
initialises with user provided initial values
Random_Init, 
initialises with random initial values
Renew, 
re-initialises 
Remove
removes the credentials
'

entrypoint="$1"
source ./bootstrap.env
VAULT_ADDR="$VAULT_ADDR" # Address of your vault server
VAULT_TOKEN="$VAULT_TOKEN" # Vault Admin Token
PROD_MODE="$PROD_MODE" # If enabled, new users will be created in the host environment
SECRETPATH="$SECRETPATH" # Where the secrets will be temporarily stored

# HOSTNAME=test
# generate_database_credentials() {
#     local database_role="$1"
#     local response

#     response=$(curl -k -s --request POST --data @new_db_user.json "$VAULT_ADDR/v1/database/static-roles/$database_role" --header "X-Vault-Token: $VAULT_TOKEN")
#     echo $response

#     # response=$(curl -k -s --request POST --data @new_db_user.json "$VAULT_ADDR/v1/database/roles/$database_role" --header "X-Vault-Token: $VAULT_TOKEN")
#     # echo $response

#     # response=$(curl -k -s --request POST --data '{}' "$VAULT_ADDR/v1/database/creds/$database_role" --header "X-Vault-Token: $VAULT_TOKEN")
#     # echo $response

#     response=$(curl -k -s --request POST --data '{}' "$VAULT_ADDR/v1/database/static-creds/$database_role" --header "X-Vault-Token: $VAULT_TOKEN")
#     echo $response
#     local username=$(echo "$response" | jq -r '.data.username')
#     local password=$(echo "$response" | jq -r '.data.password')
#     echo "Username: $username"
#     echo "Password: $password"
# }
# store_database_credentials() {
#     local database_role="$1"
#     local username="$2"
#     local password="$3"
#     local database="$4"
#     # curl --request POST $VAULT_ADDR/v1/database/Postgres/my-role -k --header "X-Vault-Token: $VAULT_TOKEN"  &&
#     curl -k --data "{\"data\": {\"db_name\": \"Postgres\", \"username\": \"$username\", \"password\": \"$password\"}}" "$VAULT_ADDR/v1/database/roles/$database_role" --header "X-Vault-Token: $VAULT_TOKEN"  &&
#     echo "Database credentials stored in Vault."
# }


generate_vault_auth(){
    # Set authentication method configuration
    auth_config='{
        "password": "'$password'",
        "token_policies": ["admin", "default"],
        "token_bound_cidrs": ["127.0.0.1/32", "128.252.0.0/16"]
    }'
    # Send request to create authentication method
    response="$(curl -k -s -X POST -H "X-Vault-Token: $VAULT_TOKEN" -d "$auth_config"  "$VAULT_ADDR/v1/auth/userpass/users/$HOSTNAME")"
    echo $response
}

generate_client_certificate() {
    openssl req -new -newkey rsa:2048 -days 365 -nodes -x509 -keyout $SECRETPATH/client.key -out ./client.crt -subj "/CN=$HOSTNAME"
}


# Note the below function cannot contain leading tabs or spaces
generate_pgp_key(){
pgp_passphrase=$password
pgp_username=$username

# Generate Key
gpg --batch --generate-key <<EOF
Key-Type: RSA
Key-Length: 2048
Name-Real: $pgp_username@$HOSTNAME
Name-Email: $pgp_username@$HOSTNAME.com
Passphrase: $pgp_passphrase
Expire-Date: 0
%commit
EOF

# Export the public key
gpg --armor --output pubkey.asc --export $pgp_username@$HOSTNAME.com
}


generate_client_user() {
    
    # Function to generate a random username
    # Array of fruit names
    fruits=("apple" "banana" "orange" "grape" "kiwi" "melon" "peach" "pear" "plum" "strawberry")
    # Array of animal names
    animals=("cat" "dog" "rabbit" "mouse" "elephant" "lion" "tiger" "zebra" "giraffe" "monkey")
    random_username() {
        fruit="${fruits[$((RANDOM % ${#fruits[@]}))]}"
        animal="${animals[$((RANDOM % ${#animals[@]}))]}"
        echo "${fruit}_${animal}"
    }

    # Use a username consisting of two random words if none sent in .env
    username=$([ "$USER" != "" ] && echo "$USER" || random_username)

    # Use a random password if none sent in .env
    password=$([ "$PASS" != "" ] && echo "$PASS" || head /dev/urandom | base64 | head -c 12)

    # Create the user with the random username and password
    if [ "$PROD_MODE" == "true" ] ; then
        useradd -m "$username"
        echo "$username:$password" | chpasswd
    fi
    echo "User created:"
    echo "Username: $username"
}


store_client_secrets() {
    request=$(curl -k --data "{\"data\": {\"username\":\"$username\",\"password\":\"$password\",\"pgp-public-key\": \"$(base64 -w 0 $SECRETPATH/pubkey.asc)\", \"cert\": \"$(base64 -w 0 $SECRETPATH/client.crt )\", \"key\": \"$(base64 -w 0 $SECRETPATH/client.key)\"}}" \
    "$VAULT_ADDR/v1/client-secrets/data/$HOSTNAME" --header "X-Vault-Token: $VAULT_TOKEN" ) &&
    echo $request
    echo "Client certificate stored in Vault."
}


retrieve_client_secret_b64(){
    key=$1
    result=$(jq -r '.data.data."'$key'"' <<< "$(curl -k --header "X-Vault-Token: $VAULT_TOKEN" --request GET $VAULT_ADDR/v1/client-secrets/data/$HOSTNAME 2>/dev/null)")
    result=$(echo $result | base64 -d)
    echo "$result"
}


retrieve_client_secret(){
    key=$1
    result=$(jq -r '.data.data."'$key'"' <<< "$(curl -k --header "X-Vault-Token: $VAULT_TOKEN" --request GET $VAULT_ADDR/v1/client-secrets/data/$HOSTNAME 2>/dev/null)")
    echo "$result"
}

encrypt_env(){
    env_file="./bootstrap.env"

    # Check if the environment file is encrypted
    if file "$env_file" | grep -q "OpenSSL encrypted"; then
        echo "Environment file is already encrypted."
    else
        # Encrypt the environment file
        echo "Encrypting environment file..."
        openssl enc -aes-256-cbc -salt -pass pass:"$password" -in "$env_file" -out "$env_file.enc"
        if [ $? -eq 0 ]; then
            echo "Environment file encrypted successfully."
            # Optionally, remove the unencrypted file
            # rm "$env_file"
        else
            echo "Failed to encrypt environment file."
        fi
    fi
}

decrypt_env(){
    encrypted_file="./bootstrap.env.enc"

    # Check if the file is encrypted
    if file "$encrypted_file" | grep -q "OpenSSL encrypted"; then
        # Decrypt the file
        echo "Decrypting $encrypted_file..."
        openssl enc -d -aes-256-cbc -pass pass:"$password" -in "$encrypted_file" -out "${encrypted_file%.enc}"
        if [ $? -eq 0 ]; then
            echo "File decrypted successfully."
        else
            echo "Failed to decrypt file."
        fi
    else
        echo "File is not encrypted with OpenSSL."
    fi
}
main() {
    decrypt_env
    generate_client_user
    generate_vault_auth
    generate_client_certificate  # Generate client certificate
    generate_pgp_key
    store_client_secrets # Store client certificate in Vault

    rm ./client.crt
    rm ./client.key
    rm ./pubkey.asc
    
    encrypt_env

    #retrieve_client_secret_b64 "cert"
    # retrieve_client_secret_b64 "key"
    # retrieve_client_secret_b64 "pgp-public-key"

    # local database_role="Admin"

    # # Generate database credentials
    # local credentials
    # credentials=$(generate_database_credentials "$database_role")
    # echo $credentials
    # if [ -n "$credentials" ]; then
    #     local username=$(echo "$credentials" | awk 'NR==1')
    #     local password=$(echo "$credentials" | awk 'NR==2')

    #     # Store database credentials in Vault
    #     store_database_credentials "$database_role" "$username" "$password" "postgres"
    # else
    #     echo "Failed to generate database credentials."
    #     exit 1
    # fi
}

apt update
apt install openssl gpg curl -y

main

# # Check if the script is run as root
# if [ "$(id -u)" != "0" ]; then
#     echo "This script must be run as root" 1>&2
#     exit 1
# fi

# # Path to the system-wide shell configuration file
# config_file="/etc/profile"

# # Check if the configuration file exists
# if [ ! -f "$config_file" ]; then
#     echo "Configuration file $config_file not found" 1>&2
#     exit 1
# fi

# # Check if the login script directive is already present in the configuration file
# if grep -q "shopt -s login_shell" "$config_file"; then
#     echo "Login shell enforcement already configured"
#     exit 0
# fi

# # Add the login shell directive to the configuration file
# echo "shopt -s login_shell" >> "$config_file"

# echo "Login shell enforcement configured successfully"


exec $entrypoint

# tail -f /dev/null