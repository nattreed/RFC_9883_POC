#include "rfc9883.h"

int main(int argc, char *argv[]){
    if (argc != 5) {
        fprintf(stderr,
                "Usage: %s <input_csr.pem> <ca_cert.pem> "
                "<ca_key.pem> <output_cert.pem>\n\n"
                "  input_csr.pem   RFC 9883 format CSR\n"
                "  ca_cert.pem     CA certificate\n"
                "  ca_key.pem      CA ML-DSA private key\n"
                "  output_cert.pem Output certificate path\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    const char *csr_path      = argv[1];
    const char *cert_path  = argv[2];
    const char *key_path   = argv[3];
    const char *kem_cert_path = argv[4];
    X509* cert = build_certificate(csr_path,cert_path,key_path,365,true);
    if(cert != NULL){
        write_certificate(cert,kem_cert_path);
    }
    return EXIT_SUCCESS;
}
