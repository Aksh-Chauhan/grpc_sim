#!/bin/bash
set -e

CERTS_DIR="certs"

echo "--- Generating TLS Certificates and Keys ---"

# Create certs directory
mkdir -p "$CERTS_DIR"
echo "Created directory: $CERTS_DIR"

# 1. Generate CA private key and certificate
echo "Generating CA private key and certificate..."
openssl genrsa -out "$CERTS_DIR/ca.key" 2048
openssl req -new -x509 -days 365 -key "$CERTS_DIR/ca.key" -out "$CERTS_DIR/ca.crt" -subj "/C=IN/ST=Telangana/L=Hyderabad/O=TestOrg/CN=TestCA"

# 2. Generate Server A private key and certificate request
echo "Generating Server A private key and certificate request..."
openssl genrsa -out "$CERTS_DIR/server_a.key" 2048
openssl req -new -key "$CERTS_DIR/server_a.key" -out "$CERTS_DIR/server_a.csr" -subj "/C=IN/ST=Telangana/L=Hyderabad/O=TestOrg/CN=server_a" -addext "subjectAltName = DNS:server_a, DNS:localhost, DNS:server_b, DNS:server_c"

# 3. Sign Server A certificate with CA
echo "Signing Server A certificate with CA..."
openssl x509 -req -days 365 -in "$CERTS_DIR/server_a.csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/server_a.crt" -extfile <(printf "subjectAltName = DNS:server_a, DNS:localhost, DNS:server_b, DNS:server_c\nextendedKeyUsage=serverAuth")

# 4. Generate Server B private key and certificate request
echo "Generating Server B private key and certificate request..."
openssl genrsa -out "$CERTS_DIR/server_b.key" 2048
openssl req -new -key "$CERTS_DIR/server_b.key" -out "$CERTS_DIR/server_b.csr" -subj "/C=IN/ST=Telangana/L=Hyderabad/O=TestOrg/CN=server_b" -addext "subjectAltName = DNS:server_a, DNS:localhost, DNS:server_b, DNS:server_c"

# 5. Sign Server B certificate with CA
echo "Signing Server B certificate with CA..."
openssl x509 -req -days 365 -in "$CERTS_DIR/server_b.csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/server_b.crt" -extfile <(printf "subjectAltName = DNS:server_a, DNS:localhost, DNS:server_b, DNS:server_c\nextendedKeyUsage=serverAuth")

# 6. Generate Server C private key and certificate request
echo "Generating Server C private key and certificate request..."
openssl genrsa -out "$CERTS_DIR/server_c.key" 2048
openssl req -new -key "$CERTS_DIR/server_c.key" -out "$CERTS_DIR/server_c.csr" -subj "/C=IN/ST=Telangana/L=Hyderabad/O=TestOrg/CN=server_c" -addext "subjectAltName = DNS:server_a, DNS:localhost, DNS:server_b, DNS:server_c"

# 7. Sign Server C certificate with CA
echo "Signing Server C certificate with CA..."
openssl x509 -req -days 365 -in "$CERTS_DIR/server_c.csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/server_c.crt" -extfile <(printf "subjectAltName = DNS:server_a, DNS:localhost, DNS:server_b, DNS:server_c\nextendedKeyUsage=serverAuth")


# 8. Generate Client private key and certificate request
echo "Generating Client private key and certificate request..."
openssl genrsa -out "$CERTS_DIR/client.key" 2048
openssl req -new -key "$CERTS_DIR/client.key" -out "$CERTS_DIR/client.csr" -subj "/C=IN/ST=Telangana/L=Hyderabad/O=TestOrg/CN=TestClient"

# 9. Sign Client certificate with CA
echo "Signing Client certificate with CA..."
openssl x509 -req -days 365 -in "$CERTS_DIR/client.csr" -CA "$CERTS_DIR/ca.crt" -CAkey "$CERTS_DIR/ca.key" -CAcreateserial -out "$CERTS_DIR/client.crt" -extfile <(printf "extendedKeyUsage=clientAuth")

echo "Certificates generated successfully in the '$CERTS_DIR' directory."
ls -l "$CERTS_DIR"
