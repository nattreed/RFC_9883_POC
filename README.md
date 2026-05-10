
# RFC 9883 Proof-Of-Concept Implementation

This repository contains the source code for a basic implementation of the Private Key Posession Statement introduced in RFC 9883. Using the template structure from OpenSSL, an attribute can easily be created for usage in the creation of a Certificate Signing Request for ML-KEM keys. Once compiled, it can be used alongside the OpenSSL CLI commands to create a fully Post Quantum certificate chain leveraging ML-DSA and ML-KEM for the keys within the chain of trust.




## Installation

As a prerequisite, ensure GCC version 14.2.0+ and OpenSSL 3.5+ are installed on your machine. From the directory of this repository, the following two commands can be used to generate the programs for creating an RFC 9883 CSR, and creating a certificate from the CSR.

```bash
  mkdir run
  gcc -o run/generate_csr src/request.c src/rfc9883.c -lssl -lcrypto -Wall -Wextra  
  gcc -o run/generate_cert src/sign.c src/rfc9883.c -lssl -lcrypto -Wall -Wextra  
```
    
## Example Usage
The following commands can be run from the command line to create a fictional PQC certificte chain that uses the RFC 9883 attribute. Replace -LEVEL with the various security levels of ML-KEM and ML-DSA desired.

```bash
openssl genpkey -algorithm ML-DSA-LEVEL -out mldsa_key.pem
openssl genpkey -algorithm ML-KEM-LEVEL -out mlkem_key.pem
openssl pkey -in mlkem_key.pem -pubout -out mlkem_pub.pem

openssl genpkey -algorithm ML-DSA-LEVEL -out root_key.pem
openssl req -new -x509 -key root_key.pem -out root_cert.pem -days 3650 -subj "/C=US/O=Fictional Root Authority/CN=Fictional Root CA"


openssl genpkey -algorithm ML-DSA-LEVEL -out ca_key.pem
openssl req -new -key ca_key.pem -out ca_csr.pem -subj "/C=US/O=Fictional Intermediate Authority/CN=Fictional ML-DSA CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl x509 -req -in ca_csr.pem -CA root_cert.pem -CAkey root_key.pem -CAcreateserial -out ca_cert.pem -days 1825 -copy_extensions copy

openssl req -new -key mldsa_key.pem -out entity_sign_csr.pem -subj "/C=US/O=Example Org/CN=example.com" -addext "keyUsage=digitalSignature"
openssl x509 -req -in entity_sign_csr.pem -CA ca_cert.pem -CAkey ca_key.pem -CAcreateserial -out entity_sign_cert.pem -days 365

openssl verify -CAfile root_cert.pem -untrusted ca_cert.pem entity_sign_cert.pem
..\path\to\repo\run\generate_csr.exe mlkem_pub.pem mldsa_key.pem entity_kem_csr.pem entity_sign_cert.pem
..\path\to\repo\run\generate_cert.exe entity_kem_csr.pem ca_cert.pem ca_key.pem entity_kem_cert.pem
openssl verify -CAfile root_cert.pem -untrusted ca_cert.pem entity_kem_cert.pem


```

