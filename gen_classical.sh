cd /certs
openssl genrsa -out ca.key 2048
openssl req -x509 -new -key ca.key -days 365 -out ca.crt -subj '/CN=Classical-CA/O=PQDemo/C=TN'
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj '/CN=localhost/O=PQDemo/C=TN'
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out server.crt
echo done
