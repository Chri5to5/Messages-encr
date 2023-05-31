#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/des.h>

#define KEY_LENGTH 2048
#define PUB_EXP 65537

void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

RSA *generateRSAKey()
{
    RSA *rsa = NULL;
    BIGNUM *bn = NULL;
    BIO *bp_private = NULL;
    int ret = 0;

    bn = BN_new();
    ret = BN_set_word(bn, PUB_EXP);
    if (ret != 1)
        handleErrors();

    rsa = RSA_new();
    ret = RSA_generate_key_ex(rsa, KEY_LENGTH, bn, NULL);
    if (ret != 1)
        handleErrors();

    bp_private = BIO_new_file("private_key.pem", "w");
    if (!PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL))
        handleErrors();

    BIO_free_all(bp_private);
    BN_free(bn);

    return rsa;
}

std::string encryptMessage(const std::string &message, const unsigned char *key)
{
    DES_key_schedule desKey;
    DES_cblock desKeyBlock;
    memcpy(desKeyBlock, key, 8);
    DES_set_key_checked(&desKeyBlock, &desKey);

    std::string encryptedText = message;
    DES_ncbc_encrypt(reinterpret_cast<const unsigned char *>(message.c_str()), reinterpret_cast<unsigned char *>(const_cast<char *>(encryptedText.c_str())), message.length(), &desKey, &desKeyBlock, DES_ENCRYPT);

    return encryptedText;
}

int main()
{
    RSA *rsaKey = generateRSAKey();

    // Simulating the server sending a message
    std::string message = "Hello, Client!";
    std::cout << "Original Message: " << message << std::endl;

    unsigned char key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    std::string encryptedMessage = encryptMessage(message, key);

    std::cout << "Encrypted Message: " << encryptedMessage << std::endl;

    RSA_free(rsaKey);

    return 0;
}
