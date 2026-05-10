#ifndef GENERATE9883_H
#define GENERATE9883_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/bn.h>

#define MAX_FIELD_LEN 256

#define SOP_OID_STR "1.3.6.1.4.1.22112.2.1"
#define SOP_SN      "RFC9883"
#define SOP_LN      "privateKeyPossessionStatement"

X509_REQ* build_9883_csr(const char* kem_path, const char* dsa_path, const char* cert_path, bool debug);
void write_9883_csr(X509_REQ *csr, const char *path);

X509* build_certificate(const char* csr_path, const char* cert_path, const char* key_path, int days, bool debug);
void write_certificate(X509 *cert, const char *path);

#endif
