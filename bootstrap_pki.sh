#!/bin/bash

source ./bootstrap.env
$VAULT_NAMESPACE="admin"
VAULT_ADDR="$VAULT_ADDR" # Address of your vault server
VAULT_TOKEN="$VAULT_TOKEN" # Vault Admin Token
PROD_MODE="$PROD_MODE" # If enabled, new users will be created in the host environment
SECRETPATH="$SECRETPATH" # Where the secrets will be temporarily stored
secret_list="$SECRETPATH/secrets.env"
echo $secret_list
echo $SECRETPATH

generate_root() {

    # Enable the pki secrets engine at pki path using /sys/mounts endpoint.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data '{"type":"pki"}' \
   $VAULT_ADDR/v1/sys/mounts/pki

    # Tune the pki secrets engine to issue certificates with a maximum time-to-live (TTL) of 87600 hours.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data '{"max_lease_ttl":"87600h"}' \
   $VAULT_ADDR/v1/sys/mounts/pki/tune

   #Create an API request payload containing the common name to set.
   tee payload.json <<EOF
{
  "common_name": "example.com",
  "issuer_name": "root-2024",
  "ttl": "87600h"
}
EOF
    # Generate the root certificate and extract the CA certificate and save it as root_2024_ca.crt.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
    --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
    --request POST \
    --data @payload.json \
    $VAULT_ADDR/v1/pki/root/generate/internal \
    | jq -r ".data.certificate" > root_2024_ca.crt

    # List the issuers.
    curl \
    --silent \
    --header "X-Vault-Request: true" \
    --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
    --header "X-Vault-Token: $(vault print token)" \
    "$VAULT_ADDR"/v1/pki/issuers\?list=true \
    | jq
    # Read the issuer with its ID to get the certificates and other metadata about the issuer.
    curl \
    --silent \
    --header "X-Vault-Token: $(vault print token)" \
    --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
    --header "X-Vault-Request: true" \
    $VAULT_ADDR/v1/pki/issuer/09c2c9a0-a874-36d2-de85-d79a7a51e373 \
    | jq

    # Create a role for the root CA; 
    # creating this role allows for specifying an issuer when necessary for the purposes of this scenario. This also provides a simple way to transition from one issuer to another by referring to it by name.
    curl \
    --silent \
    --request PUT \
    --header "X-Vault-Token: $(vault print token)" \
    --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
    --header "X-Vault-Request: true" \
    --data '{"allow_any_name":"true", "issuer_ref": "root-2024"}' \
    "$VAULT_ADDR"/v1/pki/roles/2024-servers

    # Create an API request payload containing the URLs to set.
     tee payload-url.json <<EOF
{
  "issuing_certificates": "$VAULT_ADDR/v1/pki/ca",
  "crl_distribution_points": "$VAULT_ADDR/v1/pki/crl"
}
EOF
    # Configure the CA and CRL URLs.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data @payload-url.json \
   $VAULT_ADDR/v1/pki/config/urls
}
generate_intermediate(){
    # Generate intermediate certificate
    
    # Enable the pki secrets engine at pki_int path.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data '{"type":"pki"}' \
   $VAULT_ADDR/v1/sys/mounts/pki_int

    # Tune the pki_int secrets engine to issue certificates with a maximum time-to-live (TTL) of 43800 hours.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data '{"max_lease_ttl":"43800h"}' \
   $VAULT_ADDR/v1/sys/mounts/pki_int/tune

# Create an API request payload containing the common name to set.
tee payload-int.json <<EOF
{
  "common_name": "example.com Intermediate Authority",
  "issuer_name": "example-dot-com-intermediate"
}
EOF

    # Generate an intermediate using the /pki_int/intermediate/generate/internal endpoint and save it as pki_intermediate.csr.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
    --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
    --request POST \
    --data @payload-int.json \
    $VAULT_ADDR/v1/pki_int/intermediate/generate/internal | jq -c '.data | .csr' >> pki_intermediate.csr

# Create an API request payload to sign the CSR.
tee payload-int-cert.json <<EOF
{
  "csr": $(cat pki_intermediate.csr),
  "format": "pem_bundle",
  "ttl": "43800h"
}
EOF

    # Sign the intermediate certificate with the root CA private key, and save the certificate as intermediate.cert.pem.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data @payload-int-cert.json \
   $VAULT_ADDR/v1/pki/root/sign-intermediate | jq '.data | .certificate' >> intermediate.cert.pem

# Create an API request payload containing the certificate you obtained.
tee payload-signed.json <<EOF
{
  "certificate": $(cat intermediate.cert.pem)
}
EOF

    # Submit the signed certificate.
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data @payload-signed.json \
   $VAULT_ADDR/v1/pki_int/intermediate/set-signed

}

vault_create_role(){
#Create an API request payload containing domain information to set.
tee payload-role.json <<EOF
{
  "allowed_domains": "example.com",
  "allow_subdomains": true,
  "issuer_ref": "$(vault read -field=default pki_int/config/issuers)",
  "max_ttl": "720h"
}
EOF
# Create a role named example-dot-com which allows subdomains.
curl --header "X-Vault-Token: $VAULT_TOKEN" \
--header "X-Vault-Namespace: $VAULT_NAMESPACE" \
--request POST \
--data @payload-role.json \
$VAULT_ADDR/v1/pki_int/roles/example-dot-com

}

vault_get_cert(){
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data '{"common_name": "test.example.com", "ttl": "24h"}' \
   $VAULT_ADDR/v1/pki_int/issue/example-dot-com | jq

}

revoke_regenerate(){
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data '{"serial_number": "<serial_number>"}' \
   $VAULT_ADDR/v1/pki_int/revoke | jq

}

cleanup(){
    curl --header "X-Vault-Token: $VAULT_TOKEN" \
   --header "X-Vault-Namespace: $VAULT_NAMESPACE" \
   --request POST \
   --data '{"tidy_cert_store": true, "tidy_revoked_certs": true}' \
   $VAULT_ADDR/v1/pki_int/tidy | jq
}

rotate_root(){
    curl \
    --silent \
    --request PUT \
    --header "X-Vault-Request: true" \
    --header "X-Vault-Token: $(vault print token)" \
    --data '{"common_name":"example.com","issuer_name":"root-2024"}' \
    $VAULT_ADDR/v1/pki/root/rotate/internal \
    | jq
}