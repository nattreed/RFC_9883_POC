#include "rfc9883.h"

int main(int argc, char *argv[]){
    if (argc < 4 || argc > 6) {
        fprintf(stderr,
                "Usage: %s <mlkem_pub.pem> <mldsa_priv.pem> <output.csr.pem>"
                " [possession_cert.pem] [--debug]\n\n"
                "  mlkem_pub.pem       ML-KEM public key (embedded in the CSR)\n"
                "  mldsa_priv.pem      ML-DSA private key (signs the CSR)\n"
                "  output_csr.pem      Destination for the generated CSR\n"
                "  possession_cert.pem (Optional) Certificate being claimed.\n"
                "                      Issuer/serial populate the signer field;\n"
                "                      the full cert is embedded in the cert field.\n"
                "  --debug             (Optional) Print csr contents.\n",
                argv[0]);
        return EXIT_FAILURE;
    }
    const char *mlkem_pub_path = argv[1];
    const char *mldsa_priv_path = argv[2];
    const char *output_csr_path = argv[3];
    const char *signing_cert_path = NULL;
    bool debug = false;
    for (int i = 4; i < argc; i++) {
        if (strcmp(argv[i], "--debug") == 0){
            debug = true;
        }
        else{
            signing_cert_path = argv[i];
        }
    }
    X509_REQ* csr = build_9883_csr(mlkem_pub_path,mldsa_priv_path,signing_cert_path,debug);
    write_9883_csr(csr,output_csr_path);
    return EXIT_SUCCESS;
}
