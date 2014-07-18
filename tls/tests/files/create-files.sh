#!/bin/sh

msg() {
  echo
  echo "* $1 ..."
}

echo
echo "This script re-generates all private keys and certificates"
echo "needed to run the Unit Test."
echo
echo "                   *** IMPORTANT ***"
echo
echo "This script will change the system date momentarily to generate"
echo "a couple of certificates (sudo password will be requested). This"
echo "is because it uses the OpenSSL x509 utility instead of the ca"
echo "utility which allows to set a starting date for the certificates."
echo
echo "A few manual changes need to be made. The first certificate"
echo "in ca-roots.pem and ca-roots-bad.pem need to be replaced by"
echo "the contents of ca.pem."
echo
echo "Also, file-database.c:test_lookup_certificates_issued_by has"
echo "an ISSUER variable that needs to be changed by the CA identifier"
echo "(read the comment in that function)."
echo
echo "                   *** IMPORTANT ***"
echo

read -p "Press [Enter] key to continue..." key

# Create serial file
echo "00" > serial

msg "Creating CA private key"
openssl genrsa -out ca-key.pem 1024

msg "Creating CA certificate"
openssl req -x509 -new -config ssl/ca.conf -days 10950 -key ca-key.pem -out ca.pem

msg "Creating server private key"
openssl genrsa -out server-key.pem 512

msg "Creating server certificate request"
openssl req -config ssl/server.conf -key server-key.pem -new -out server-csr.pem

msg "Creating server certificate"
openssl x509 -req -in server-csr.pem -days 9125 -CA ca.pem -CAkey ca-key.pem -CAserial serial -extfile ssl/server.conf -extensions v3_req_ext -out server.pem

msg "Concatenating server certificate and private key into a single file"
cat server.pem > server-and-key.pem
cat server-key.pem >> server-and-key.pem

msg "Converting server certificate from PEM to DER"
openssl x509 -in server.pem -outform DER -out server.der

msg "Converting server private key from PEM to DER"
openssl rsa -in server-key.pem -outform DER -out server-key.der

msg "Creating server self-signed certificate"
openssl x509 -req -days 9125 -in server-csr.pem -signkey server-key.pem -out server-self.pem

msg "Creating client private key"
openssl genrsa -out client-key.pem 2048

msg "Creating client certificate request"
openssl req -config ssl/client.conf -key client-key.pem -new -out client-csr.pem

msg "Creating client certificate"
openssl x509 -req -in client-csr.pem -days 9125 -CA ca.pem -CAkey ca-key.pem -CAserial serial -out client.pem

msg "Concatenating client certificate and private key into a single file"
cat client.pem > client-and-key.pem
cat client-key.pem >> client-and-key.pem

# It is not possible to specify the start and end date using the "x509" tool.
# It would be better to use the "ca" tool. Sorry!
msg "Creating client certificate (past)"
sudo date -s "17 JUL 2000 18:00:00"
openssl x509 -req -in client-csr.pem -days 365 -startdate -enddate -CA ca.pem -CAkey ca-key.pem -CAserial serial -out client-past.pem
sudo hwclock -s
touch client-past.pem

msg "Creating client certificate (future)"
sudo date -s "17 JUL 2060 18:00:00"
openssl x509 -req -in client-csr.pem -days 365 -startdate -enddate -CA ca.pem -CAkey ca-key.pem -CAserial serial -out client-future.pem
sudo hwclock -s
touch client-future.pem

msg "Concatenating all non-CA certificates into a single file"
echo "client.pem:" > non-ca.pem
cat client.pem >> non-ca.pem
echo >> non-ca.pem
echo "client-future.pem:" >> non-ca.pem
cat client-future.pem >> non-ca.pem
echo >> non-ca.pem
echo "client-past.pem:" >> non-ca.pem
cat client-past.pem >> non-ca.pem
echo >> non-ca.pem
echo "server.pem:" >> non-ca.pem
cat server.pem >> non-ca.pem
echo >> non-ca.pem
echo "server-self.pem:" >> non-ca.pem
cat server-self.pem >> non-ca.pem

# We don't need the serial file anymore
rm -f serial
