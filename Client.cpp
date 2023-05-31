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

RSA *loadPublicKey()
{
    RSA *rsa = NULL;
    BIO *bp_public = NULL;

    bp_public = BIO_new_file("public_key.pem", "r");
    if (!bp_public)
        handleErrors();

    rsa = PEM_read_bio_RSAPublicKey(bp_public, NULL, NULL, NULL);
    if (!rsa)
        handleErrors();

    BIO_free_all(bp_public);

    return rsa;
}

std::string decryptMessage(const std::string &encryptedMessage, const unsigned char *key)
{
    DES_key_schedule desKey;
    DES_cblock desKeyBlock;
    memcpy(desKeyBlock, key, 8);
    DES_set_key_checked(&desKeyBlock, &desKey);

    std::string decryptedText = encryptedMessage;
    DES_ncbc_encrypt(reinterpret_cast<const unsigned char *>(encryptedMessage.c_str()), reinterpret_cast<unsigned char *>(const_cast<char *>(decryptedText.c_str())), encryptedMessage.length(), &desKey, &desKeyBlock, DES_DECRYPT);

    return decryptedText;
}

int main()
{
    RSA *rsaKey = loadPublicKey();

    // Simulating the client receiving the encrypted message
    std::string receivedMessage = "SomeEncryptedText";

    unsigned char key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    std::string decryptedMessage = decryptMessage(receivedMessage, key);

    std::cout << "Decrypted Message: " << decryptedMessage << std::endl;

    RSA_free(rsaKey);

    return 0;
}
