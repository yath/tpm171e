/* a tool written for decrypting the firmware available for Philips-Android-TVs (AND1.E...) 
 * see: http://forum.xda-developers.com/android/help/philips-android-tv-t2935545
 * compile: gcc -std=c99 decrypt-firmware.c -o decrypt-firmware.o -l crypto
 *
 * 5003b4d49cbf7916123271b7b1918f123cca0c09bf1428f4398257751ac6570c (google for it for more information)
 *
 * Updated with key for TPM171E by yath.
 * (adb pull /system/etc/recovery-resource.dat rr.zip && unzip rr.zip keyfile.txt)
 */

#include <stdio.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

int main( int argc, const char* argv[] ) {

    if (argc < 2) {
        printf("USAGE:\n");
        printf("\t%s [INPUT-FILE]\n", argv[0]);
        return 0;
    }



    char *subKey =    "\xfe\xfe\xe9\x91\xa8\xb1\x28\x34\x6a\x32\xc2\xe3\x37\xc1\x8d\x9c"
                    "\xb2\x1f\x3b\xe2\x90\x90\x2b\xbc\xa2\x63\xff\x2b\x1c\x55\xd6\xe4"
                    "\x0f\x65\x0e\xf3\x7b\xdc\x23\x10\xb7\x7a\x9e\x25\xe6\x84\x16\xfb"
                    "\x43\xbc\x63\x32\xcb\xce\x01\xc2\x87\x65\x52\xd4\xab\xd1\xc7\x5d"
                    "\x4b\xe0\xa3\xff\xf4\x99\x8d\xa9\x5d\xf0\x2f\xe6\x70\x3e\xc6\xf0"
                    "\x3f\xf3\x65\xce\x38\x58\x3d\x74\x32\x72\xe6\x20\x5d\xb1\x7a\x44"
                    "\xb3\xe4\xb2\x64\x6b\x06\x4b\x3e\xb2\xa7\x10\x80\x23\x72\xfe\xca"
                    "\x17\x4d\x43\x1b\x41\xaf\xa3\x39\x56\x29\xc9\x2b\x12\xf9\x66\xed";
    
    unsigned char key[257];
    unsigned char iv[129];
    unsigned char salt[9];
    
    BIO *encrypted;
    BIO *encryptor;
    BIO *decrypted;
    
    EVP_CIPHER_CTX* ctx;
    const EVP_CIPHER* cipher;
    const EVP_MD* md;
    
    char inputFile[200];
    char outputFile[200];
    
    int retValue;
    
    snprintf(inputFile, 199, "%s", argv[1]);
    snprintf(outputFile, 199, "%s.dec", inputFile);
    
    printf("decrypting '%s' and storing it into '%s'\n", inputFile, outputFile);
    
    OpenSSL_add_all_algorithms();
    cipher = EVP_get_cipherbyname("aes-256-cbc");
    if (!cipher) {
        printf("error getting cipher\n");
        return 0;
    }
    
    md = EVP_md5();
    if (!md) {
        printf("error getting message digest\n");
        return 0;
    }
    
    encrypted = BIO_new(BIO_s_file());
    if (!encrypted) {
        printf("error getting encrypted bio\n");
        return 0;
    }
    
    retValue = BIO_ctrl(encrypted, BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_READ, inputFile);
    if (!retValue) {
        printf("error opening encrypted zip\n");
        return 0;
    }
    
    BIO_read(encrypted, salt, 8);
    if (memcmp(salt, "Salted__", 8) != 0) {
        printf("wrong file given\n");
        return 0;
    }

    BIO_read(encrypted, salt, 8);
    printf("salt: ");
    for(int i=0; i<8; i++) {
        printf("%x ", (unsigned) (unsigned char) salt[i]);
    }
    printf("\n");
    
    decrypted = BIO_new(BIO_s_file());
    if (!decrypted) {
        printf("error getting decrypted bio\n");
        return 0;
    }
    
    retValue = BIO_ctrl(decrypted, BIO_C_SET_FILENAME, BIO_CLOSE|BIO_FP_WRITE, outputFile);
    if (!retValue) {
        printf("error opening decrypted zip for writing\n");
        return 0;
    }    
    
    EVP_BytesToKey(cipher, md, salt, subKey, 127, 1, key, iv);
    printf("first eight bytes of the actual key: ");
    for(int i=0; i<8; i++) {
        printf("%x ", (unsigned) key[i]);
    }
    printf("\n");
    
    encryptor = BIO_new(BIO_f_cipher());
    if (!encryptor) {
        printf("error getting encryptor\n");
        return 0;
    }
    
    BIO_ctrl(encryptor, BIO_C_GET_CIPHER_CTX, 0, &ctx);
    if (!ctx) {
        printf("failed to get crypto ctx\n");
        return 0;
    }
    
    retValue = EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, 0);
    if (!retValue) {
        printf("error setting up encryptor\n");
        return 0;
    }

    retValue = EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0);
    if (!retValue) {
        printf("error setting up encryptor key and iv\n");
        return 0;
    }
    
    BIO_push(encryptor, decrypted);
    
    char buffer[1024];
    
    do {
    
        int read = BIO_read(encrypted, buffer, 1023);
        if (!read) {
            printf("no more bytes to read\n");
            break;
        }
        
        int written = BIO_write(encryptor, buffer, 1023);
        printf("written %d bytes\n", written);

    } while (1 == 1);    
    
    BIO_flush(decrypted);
    
    printf("done\n");
    
    BIO_free(encrypted);
    BIO_free(decrypted);
    BIO_free(encryptor);

}
