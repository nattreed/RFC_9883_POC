#include "rfc9883.h"

//leverage the ASN1 template to implement 
//the key posession statement attribute
//as defined in asn1t.h
typedef struct 
{
    X509_NAME    *issuer;
    ASN1_INTEGER *serialNumber;
} ISSUER_AND_SERIAL;

ASN1_SEQUENCE(ISSUER_AND_SERIAL) = {
    ASN1_SIMPLE(ISSUER_AND_SERIAL, issuer,       X509_NAME),
    ASN1_SIMPLE(ISSUER_AND_SERIAL, serialNumber, ASN1_INTEGER)
} ASN1_SEQUENCE_END(ISSUER_AND_SERIAL)

IMPLEMENT_ASN1_FUNCTIONS(ISSUER_AND_SERIAL)

typedef struct {
    ISSUER_AND_SERIAL *signer;
    X509              *cert;
} PRIVATE_KEY_POSSESSION_STMT;

ASN1_SEQUENCE(PRIVATE_KEY_POSSESSION_STMT) = {
    ASN1_SIMPLE(PRIVATE_KEY_POSSESSION_STMT, signer, ISSUER_AND_SERIAL),
    ASN1_OPT(PRIVATE_KEY_POSSESSION_STMT,    cert,   X509)
} ASN1_SEQUENCE_END(PRIVATE_KEY_POSSESSION_STMT)

IMPLEMENT_ASN1_FUNCTIONS(PRIVATE_KEY_POSSESSION_STMT)

//error handler function
static void handleSSLError(const char * msg)
{
    fprintf(stderr, "OpenSSL Error: %s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

static int register_sop_oid(void){
    int nid = OBJ_txt2nid(SOP_OID_STR);
    if (nid == NID_undef) {
        nid = OBJ_create(SOP_OID_STR, SOP_SN, SOP_LN);
        if (nid == NID_undef){
            handleSSLError("Could not register OID: " SOP_OID_STR);
        }
    }
    return nid;
}

//various functions for reading in necessary PEM files
static EVP_PKEY *load_public_key(const char *path){
    BIO *bio = BIO_new_file(path, "r");
    if (!bio){
        handleSSLError("Could not open public key file");
    }
    EVP_PKEY *pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey){
        handleSSLError("Could not parse public key file");
    }
    return pkey;
}

static EVP_PKEY *load_private_key(const char *path){
    BIO *bio = BIO_new_file(path, "r");
    if (!bio){
        handleSSLError("Could not open private key file");
    }
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey){
        handleSSLError("Could not parse private key file");
    }
    return pkey;
}

static X509_REQ *load_csr(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    if (!bio)
        handleSSLError("Could not open CSR file");

    X509_REQ *csr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
    BIO_free(bio);

    if (!csr)
        handleSSLError("Could not parse CSR");

    return csr;
}

static X509 *load_certificate(const char *path)
{
    BIO *bio = BIO_new_file(path, "r");
    if (!bio){
        handleSSLError("Could not open certificate file");
    }
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert){
        handleSSLError("Could not parse certificate, please verify it is a PEM encoded certificate file");
    }
    return cert;
}

//function for prompting a specific field that the user may input data for, similar to OpenSSL's interface
static void prompt_field(const char* prompt, const char* default_val, char* result, size_t out_len)
{
    if (default_val && default_val[0] != '\0'){
        printf("%s [%s]: ", prompt, default_val);
    }
    else{
        printf("%s []: ", prompt);
    }
    fflush(stdout);
    if (!fgets(result, (int)out_len, stdin)){
        handleSSLError("Failed to get user input");
    }
    size_t len = strlen(result);
    if (len > 0 && result[len - 1] == '\n'){
        result[len - 1] = '\0';
    }
    if (result[0] == '\0' && default_val){
        strncpy(result, default_val, out_len - 1);
    }
}

//function to add a field to the subject info
static void add_name_field(X509_NAME* name, const char* field, const char* value)
{
    if (value[0] == '\0'){
        return;
    }
    if (!X509_NAME_add_entry_by_txt(name, field, MBSTRING_ASC, (const unsigned char *)value, -1, -1, 0)){
        handleSSLError("Failed to add name entry");
    }
}

//overarching function for prompting the fields typically present when creating a CSR with OpenSSL
static X509_NAME* prompt_subject_info(void)
{
    char country[MAX_FIELD_LEN]  = {0};
    char state[MAX_FIELD_LEN]    = {0};
    char locality[MAX_FIELD_LEN] = {0};
    char org[MAX_FIELD_LEN]      = {0};
    char ou[MAX_FIELD_LEN]       = {0};
    char cn[MAX_FIELD_LEN]       = {0};
    char email[MAX_FIELD_LEN]    = {0};
    printf("You are about to be asked to enter information that will be\n"
           "incorporated into your certificate request.\n"
           "What you are about to enter is what is called a Distinguished\n"
           "Name or a DN. There are quite a few fields but you can leave\n"
           "some blank. For some fields there will be a default value.\n"
           "If you enter '.', the field will be left blank.\n\n");
    prompt_field("Country Name (2 letter code)",           "AU", country,  sizeof(country));
    prompt_field("State or Province Name (full name)",     "",   state,    sizeof(state));
    prompt_field("Locality Name (eg, city)",               "",   locality, sizeof(locality));
    prompt_field("Organization Name (eg, company)",        "",   org,      sizeof(org));
    prompt_field("Organizational Unit Name (eg, section)", "",   ou,       sizeof(ou));
    prompt_field("Common Name (e.g. server FQDN or YOUR name)", "", cn,    sizeof(cn));
    prompt_field("Email Address",                          "",   email,    sizeof(email));
    X509_NAME *name = X509_NAME_new();
    if(!name){
        handleSSLError("Could not allocate X509_NAME object");
    }
    if (strcmp(country,  ".") != 0) add_name_field(name, "C",            country);
    if (strcmp(state,    ".") != 0) add_name_field(name, "ST",           state);
    if (strcmp(locality, ".") != 0) add_name_field(name, "L",            locality);
    if (strcmp(org,      ".") != 0) add_name_field(name, "O",            org);
    if (strcmp(ou,       ".") != 0) add_name_field(name, "OU",           ou);
    if (strcmp(cn,       ".") != 0) add_name_field(name, "CN",           cn);
    if (strcmp(email,    ".") != 0) add_name_field(name, "emailAddress", email);
    return name;
}

//function for prompting the challenge password and an optional company name, as typically seen in OpenSSL
static void prompt_extra_attributes(X509_REQ* csr)
{
    char challenge[MAX_FIELD_LEN]    = {0};
    char company_name[MAX_FIELD_LEN] = {0};
    printf("\nPlease enter the following 'extra' attributes\n"
           "to be sent with your certificate request\n\n");
    prompt_field("A challenge password",     "", challenge,    sizeof(challenge));
    prompt_field("An optional company name", "", company_name, sizeof(company_name));
    if (challenge[0] != '\0' && strcmp(challenge, ".") != 0) {
        if (!X509_REQ_add1_attr_by_NID(csr, 
                                        NID_pkcs9_challengePassword,
                                        MBSTRING_ASC, 
                                        (const unsigned char *)challenge, -1)){
            handleSSLError("Failed to add extra attribute for challenge password");
        }
    }
    if (company_name[0] != '\0' && strcmp(company_name, ".") != 0) {
        if (!X509_REQ_add1_attr_by_NID(csr,
                                        NID_pkcs9_unstructuredName,
                                        MBSTRING_ASC,
                                        (const unsigned char *)company_name, -1)){
            handleSSLError("Failed to add company name attribute");
        }
    }
}

//function for adding the signature key cert into the posession attribute
static void add_signing_cert(PRIVATE_KEY_POSSESSION_STMT *stmt, X509 *signing_cert)
{
    stmt->signer->issuer = X509_NAME_dup(X509_get_issuer_name(signing_cert));
    if (!stmt->signer->issuer)
        handleSSLError("Failed to copy issuer name from signing key cert");
    stmt->signer->serialNumber =
        ASN1_INTEGER_dup(X509_get0_serialNumber(signing_cert));
    if (!stmt->signer->serialNumber)
        handleSSLError("Failed to copy serial number from signing key cert");
    stmt->cert = X509_dup(signing_cert);
    if (!stmt->cert)
        handleSSLError("Failed to copy signing key certificate");
}

//function for encoding the key possession statement and adding it into the CSR
static void encode_sop_attribute(PRIVATE_KEY_POSSESSION_STMT *stmt, X509_REQ *csr, int sop_nid)
{
    unsigned char *encoding = NULL;
    int encoding_len = i2d_PRIVATE_KEY_POSSESSION_STMT(stmt, &encoding);
    if (encoding_len < 0)
        handleSSLError("Failed to DER-encode PRIVATE_KEY_POSSESSION_STMT");
    if (!X509_REQ_add1_attr_by_NID(csr, sop_nid, V_ASN1_SEQUENCE, encoding, encoding_len))
        handleSSLError("Failed to add id-at-statementOfPossession attribute to CSR");
    OPENSSL_free(encoding);
}

//function for creating the statement of possession attribute
static void add_sop_attribute(X509_REQ *csr, int sop_nid, X509 *signing_cert)
{
    PRIVATE_KEY_POSSESSION_STMT *stmt = PRIVATE_KEY_POSSESSION_STMT_new();
    if (!stmt)
        handleSSLError("Failed to allocate PRIVATE_KEY_POSSESSION_STMT");
    if (signing_cert) {
        add_signing_cert(stmt,signing_cert);
    }
    else {
        stmt->signer->issuer = X509_NAME_new();
        if (!stmt->signer->issuer)
            handleSSLError("Failed to allocate placeholder issuer name");
        if (!X509_NAME_add_entry_by_txt(stmt->signer->issuer,
                                        "CN", MBSTRING_ASC,
                                        (const unsigned char *)"TEMPORARY ISSUER",
                                        -1, -1, 0))
            handleSSLError("Failed to set placeholder issuer CN");
        stmt->signer->serialNumber = ASN1_INTEGER_new();
        if (!stmt->signer->serialNumber)
            handleSSLError("Failed to allocate placeholder serial number");
        if (!ASN1_INTEGER_set(stmt->signer->serialNumber, 0))
            handleSSLError("Failed to set placeholder serial number value");
    }
    encode_sop_attribute(stmt,csr,sop_nid);
    PRIVATE_KEY_POSSESSION_STMT_free(stmt);
}

//function for reading a statement of possession attribute for use in certificate creation
static PRIVATE_KEY_POSSESSION_STMT *extract_sop_attribute(X509_REQ *req, int sop_nid)
{
    int attr_idx = X509_REQ_get_attr_by_NID(req, sop_nid, -1);
    if (attr_idx == -1)
        handleSSLError("CSR does not contain id-at-statementOfPossession attribute");

    X509_ATTRIBUTE *attr = X509_REQ_get_attr(req, attr_idx);
    if (!attr)
        handleSSLError("Could not retrieve SOP attribute");

    ASN1_TYPE *attr_val = X509_ATTRIBUTE_get0_type(attr, 0);
    if (!attr_val)
        handleSSLError("SOP attribute has no value");

    if ((attr_val->type & ~V_ASN1_CONSTRUCTED) != V_ASN1_SEQUENCE)
        handleSSLError("SOP attribute has unexpected value type");

    ASN1_STRING         *seq      = attr_val->value.sequence;
    int                  seq_len  = ASN1_STRING_length(seq);
    const unsigned char *data     = ASN1_STRING_get0_data(seq);

    PRIVATE_KEY_POSSESSION_STMT *stmt =
        d2i_PRIVATE_KEY_POSSESSION_STMT(NULL, &data, seq_len);

    if (!stmt)
        handleSSLError("Failed to decode PrivateKeyPossessionStatement");

    return stmt;
}

//helper function for printing a statement of posession
static void print_statement(PRIVATE_KEY_POSSESSION_STMT *stmt){
    printf("    id-at-statementOfPossession (OID: %s):\n", SOP_OID_STR);
    printf("        signer (IssuerAndSerialNumber):\n");
    if (stmt->signer && stmt->signer->issuer) {
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            X509_NAME_print_ex(bio, stmt->signer->issuer, 0, XN_FLAG_ONELINE);
            char *s = NULL;
            long  len = BIO_get_mem_data(bio, &s);
            printf("            issuer:       %.*s\n", (int)len, s);
            BIO_free(bio);
        }
    } else {
        printf("            issuer:       no data given\n");
    }
    if (stmt->signer && stmt->signer->serialNumber) {
        BIGNUM *bn = ASN1_INTEGER_to_BN(stmt->signer->serialNumber, NULL);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            printf("            serialNumber: %s\n", hex ? hex : "<error>");
            OPENSSL_free(hex);
            BN_free(bn);
        }
    } else {
        printf("            serialNumber: no data given\n");
    }
    if (stmt->cert) {
        printf("        cert (Certificate) [present]:\n");
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            X509_NAME_print_ex(bio, X509_get_subject_name(stmt->cert),
                               0, XN_FLAG_ONELINE);
            char *s = NULL;
            long  len = BIO_get_mem_data(bio, &s);
            printf("            subject:      %.*s\n", (int)len, s);
            BIO_free(bio);
        }
        bio = BIO_new(BIO_s_mem());
        if (bio) {
            X509_NAME_print_ex(bio, X509_get_issuer_name(stmt->cert),
                                0, XN_FLAG_ONELINE);
            char *s = NULL;
            long  len = BIO_get_mem_data(bio, &s);
            printf("            issuer:       %.*s\n", (int)len, s);
            BIO_free(bio);
        }
        BIGNUM *bn = ASN1_INTEGER_to_BN(
                         X509_get0_serialNumber(stmt->cert), NULL);
        if (bn) {
            char *hex = BN_bn2hex(bn);
            printf("            serialNumber: %s\n", hex ? hex : "<error>");
            OPENSSL_free(hex);
            BN_free(bn);
        }
        BIO *vbio = BIO_new(BIO_s_mem());
        if (vbio) {
            ASN1_TIME_print(vbio, X509_get0_notBefore(stmt->cert));
            char *s = NULL;
            long  len = BIO_get_mem_data(vbio, &s);
            printf("            notBefore:    %.*s\n", (int)len, s);
            BIO_free(vbio);
        }
        vbio = BIO_new(BIO_s_mem());
        if (vbio) {
            ASN1_TIME_print(vbio, X509_get0_notAfter(stmt->cert));
            char *s = NULL;
            long  len = BIO_get_mem_data(vbio, &s);
            printf("            notAfter:     %.*s\n", (int)len, s);
            BIO_free(vbio);
        }
    } else {
        printf("        cert (Certificate): not present\n");
    }
}

//helper function for fetching the statement attribute, passing it off to the helper function for printing
static void print_sop_attribute(X509_REQ* csr, int sop_nid){
    int attr_idx = X509_REQ_get_attr_by_NID(csr, sop_nid, -1);
    if (attr_idx == -1) {
        handleSSLError("id-at-statementOfPossession not present in CSR");
        return;
    }
    X509_ATTRIBUTE *attr = X509_REQ_get_attr(csr, attr_idx);
    if (!attr) {
        handleSSLError("id-at-statementOfPossession could not be extracted from CSR");
        return;
    }
    ASN1_TYPE *attr_val = X509_ATTRIBUTE_get0_type(attr, 0);
    if (!attr_val) {
        handleSSLError("id-at-statementOfPossession does not contain a value");
        return;
    }
    if ((attr_val->type & ~V_ASN1_CONSTRUCTED) != V_ASN1_SEQUENCE) {
        printf("id-at-statementOfPossession constains unexpected value type %d ", attr_val->type);
        return;
    }
    ASN1_STRING *seq = attr_val->value.sequence;
    int seq_len = ASN1_STRING_length(seq);
    const unsigned char *data = ASN1_STRING_get0_data(seq);
    PRIVATE_KEY_POSSESSION_STMT *stmt = d2i_PRIVATE_KEY_POSSESSION_STMT(NULL, &data, seq_len);
    if (!stmt) {
        handleSSLError("id-at-statementOfPossession could not be decoded");
        return;
    }
    print_statement(stmt);
    PRIVATE_KEY_POSSESSION_STMT_free(stmt);
}

//helper function for printing out a CSR
static void print_csr(X509_REQ *csr, int sop_nid)
{
    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!out){
        handleSSLError("Could not create output BIO");
    }
    if (!X509_REQ_print_ex(out, csr, XN_FLAG_MULTILINE, X509_FLAG_COMPAT)){
        handleSSLError("Could not print CSR contents");
    }
    BIO_free(out);
    print_sop_attribute(csr,sop_nid);
}

//driving function for building an RFC 9883 CSR
X509_REQ* build_9883_csr(const char* kem_path, const char* dsa_path, const char* cert_path, bool debug)
{
    int sop_nid = register_sop_oid();
    EVP_PKEY *mlkem_pubkey  = load_public_key(kem_path);
    EVP_PKEY *mldsa_privkey = load_private_key(dsa_path);
    X509_REQ *csr = X509_REQ_new();
    X509 *signing_cert = NULL;
    if (cert_path) {
        signing_cert = load_certificate(cert_path);
    }
    if (!csr){
        handleSSLError("Failed to allocate CSR object");
    }
    X509_NAME *subject = prompt_subject_info();
    if (!X509_REQ_set_version(csr, 0)){
        handleSSLError("Failed to set CSR version");
    }
    if (!X509_REQ_set_subject_name(csr, subject)){
        handleSSLError("Failed to set subject name in CSR");
    }
    if (!X509_REQ_set_pubkey(csr, mlkem_pubkey)){
        handleSSLError("Failed to store ML-KEM public key in CSR");
    }
    X509_NAME_free(subject);
    prompt_extra_attributes(csr);
    add_sop_attribute(csr, sop_nid, signing_cert);
    if (X509_REQ_sign(csr, mldsa_privkey, NULL) == 0)
        handleSSLError("Failed to sign CSR with ML-DSA private key");
    if(debug){
        printf("\n=== Generated CSR Contents ===\n\n");
        print_csr(csr,sop_nid);
    }
    EVP_PKEY_free(mlkem_pubkey);
    EVP_PKEY_free(mldsa_privkey);
    if (signing_cert) X509_free(signing_cert);
    return csr;
}

//helper function for writing the CSR to a file
void write_9883_csr(X509_REQ *csr, const char *path)
{
    unsigned char *encoding = NULL;
    int encoding_len = i2d_X509_REQ(csr, &encoding);
    if (encoding_len < 0) {
        handleSSLError("Failed to encode CSR");
    } 
    else {
        OPENSSL_free(encoding);
    }
    BIO *bio = BIO_new_file(path, "w");
    if (!bio){
        handleSSLError("Could not open output CSR file for writing");
    }
    if (!PEM_write_bio_X509_REQ(bio, csr)){
        handleSSLError("Failed to write CSR to file");
    }
    X509_REQ_free(csr);
    BIO_free(bio);
}

//function for creating a serial number for the certificate
static ASN1_INTEGER *generate_serial(void)
{
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (!serial)
        handleSSLError("Failed to allocate serial number");
    BIGNUM *bn = BN_new();
    if (!bn)
        handleSSLError("Failed to allocate BIGNUM for serial");
    if (!BN_rand(bn, 128, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY))
        handleSSLError("Failed to generate random serial number");
    if (!BN_to_ASN1_INTEGER(bn, serial))
        handleSSLError("Failed to convert serial BIGNUM to ASN1_INTEGER");
    BN_free(bn);
    return serial;
}

//helper function for printing the certificate contents
static void print_cert_summary(X509 *cert)
{
    printf("\n=== Issued Certificate Summary ===\n\n");
    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (!bio)
        handleSSLError("Could not create output BIO");
    X509_print_ex(bio, cert, XN_FLAG_MULTILINE, X509_FLAG_COMPAT);
    BIO_free(bio);
}

//function for the verification of the CSR signature
static bool verify_csr_signature(X509_REQ *csr, PRIVATE_KEY_POSSESSION_STMT *stmt)
{
    if (!stmt->cert)
        handleSSLError("PrivateKeyPossessionStatement contains no certificate — "
            "cannot verify CSR signature");
    EVP_PKEY *mldsa_pubkey = X509_get0_pubkey(stmt->cert);
    if (!mldsa_pubkey)
        handleSSLError("Could not extract public key from possession certificate");
    int result = X509_REQ_verify(csr, mldsa_pubkey);
    if (result < 0){
        handleSSLError("Error during CSR signature verification");
        return false;
    }
    if (result == 0){
        handleSSLError("CSR signature verification FAILED — "
            "the requester cannot prove possession of the ML-DSA private key");
        return false;
    }
    return true;
}

//diriving function for building the certificate from the 9883 CSR
X509* build_certificate(const char* csr_path, const char* cert_path, const char* key_path, int days, bool debug){
    int sop_nid = register_sop_oid();
    X509_REQ *csr     = load_csr(csr_path);
    X509     *ca_cert = load_certificate(cert_path);
    EVP_PKEY *ca_key  = load_private_key(key_path);
    PRIVATE_KEY_POSSESSION_STMT *stmt = extract_sop_attribute(csr, sop_nid);
    if(verify_csr_signature(csr,stmt)){
        X509 *cert = X509_new();
        if (!cert)
            handleSSLError("Failed to allocate X509");
        if (!X509_set_version(cert, 2))
            handleSSLError("Failed to set certificate version");
        ASN1_INTEGER *serial = generate_serial();
        if (!X509_set_serialNumber(cert, serial))
            handleSSLError("Failed to set serial number");
        ASN1_INTEGER_free(serial);
        if (!X509_gmtime_adj(X509_getm_notBefore(cert), 0))
            handleSSLError("Failed to set notBefore");
        if (!X509_gmtime_adj(X509_getm_notAfter(cert), (long)days * 86400))
            handleSSLError("Failed to set notAfter");
        X509_NAME *subject = X509_REQ_get_subject_name(csr);
        if (!X509_set_subject_name(cert, subject))
            handleSSLError("Failed to set subject name");
        X509_NAME *issuer = X509_get_subject_name(ca_cert);
        if (!X509_set_issuer_name(cert, issuer))
            handleSSLError("Failed to set issuer name");
        EVP_PKEY *mlkem_pubkey = X509_REQ_get0_pubkey(csr);
        if (!mlkem_pubkey)
            handleSSLError("Failed to get ML-KEM public key from CSR");
        if (!X509_set_pubkey(cert, mlkem_pubkey))
            handleSSLError("Failed to set ML-KEM public key on certificate");
        X509V3_CTX ctx;
        X509V3_set_ctx(&ctx, ca_cert, cert, NULL, NULL, 0);
        X509_EXTENSION *ext =
            X509V3_EXT_conf_nid(NULL, &ctx,
                                NID_subject_key_identifier, "hash");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        ext = X509V3_EXT_conf_nid(NULL, &ctx,
                                NID_authority_key_identifier,
                                "keyid:always,issuer");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        ext = X509V3_EXT_conf_nid(NULL, &ctx,
                                NID_basic_constraints, "CA:FALSE");
        if (ext) {
            X509_add_ext(cert, ext, -1);
            X509_EXTENSION_free(ext);
        }
        if (!X509_sign(cert, ca_key, NULL))
            handleSSLError("Failed to sign certificate with CA key");
        if(debug){
            print_cert_summary(cert);
        }
        PRIVATE_KEY_POSSESSION_STMT_free(stmt);
        X509_REQ_free(csr);
        X509_free(ca_cert);
        EVP_PKEY_free(ca_key);
        return cert;
    }
    PRIVATE_KEY_POSSESSION_STMT_free(stmt);
    X509_REQ_free(csr);
    X509_free(ca_cert);
    EVP_PKEY_free(ca_key);
    return NULL;
}

//helper function for writing the x.509 certificate out
void write_certificate(X509 *cert, const char *path){
    BIO *bio = BIO_new_file(path, "w");
    if (!bio)
        handleSSLError("Could not open output certificate file");

    if (!PEM_write_bio_X509(bio, cert))
        handleSSLError("Failed to write certificate");

    BIO_free(bio);
    X509_free(cert);
}

