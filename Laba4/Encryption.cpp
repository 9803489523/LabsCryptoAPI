#include "Encryption.h"
 //path: C:\C++\read.txt
//#define DEBUG
//#define DEBUG_READ
 
void writeFunc(bool func) {
    const char* result;
    if (func)
        result = "success";
    else
        result = "failed";
    std::cout << result << "\n";
}
 
PBYTE encrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* msg
)
{
    DWORD lengthEncrypt = strlen(msg);
#ifdef DEBUG_READ
    printf("strlen msg: %d\n", lengthEncrypt);
#endif
    PBYTE encrypt = (PBYTE)malloc(lengthEncrypt);
    strcpy((char*)encrypt, msg);
    std::cout << encrypt << "\n";
#ifdef DEBUG
    printf("Encryption...\n\n");
#endif
 
    deriveKey(prov, hash, key, secret);
 
#ifdef DEBUG
    printf("CryptEncrypt(): ");
    writeFunc(
#endif
        CryptEncrypt(*key, 0, 1, 0, encrypt, &lengthEncrypt, lengthEncrypt)
#ifndef DEBUG
        ;
#endif
#ifdef DEBUG
    );
#endif
#ifdef DEBUG
    printf("\nEnd encryption\n");
#endif
    return encrypt;
}
 
PBYTE decrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* encrypt
)
{
    DWORD lengthEncrypt = strlen(encrypt);
    PBYTE decrypt = (PBYTE)malloc(lengthEncrypt*5);
    strcpy((char*)decrypt, encrypt);
#ifdef DEBUG
    printf("Decription...\n\n");
#endif
 
    deriveKey(prov, hash, key, secret);
 
#ifdef DEBUG
    printf("CryptDecrypt(): ");
    writeFunc(
#endif
        CryptDecrypt(*key, 0, 1, 0, decrypt, &lengthEncrypt)
#ifndef DEBUG
        ;
#endif
#ifdef DEBUG
    );
#endif
#ifdef DEBUG
    printf("\nEnd decryption\n");
#endif
    return decrypt;
}
 
void deriveKey(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret
)
{
    char* trueSecret = (char*)malloc(strlen(secret));
#ifdef DEBUG
    printf("CryptAcquireContext(): ");
    writeFunc(
#endif
        CryptAcquireContext(prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
#ifndef DEBUG
        ;
#endif
#ifdef DEBUG
    );
#endif
 
#ifdef DEBUG
    printf("CryptCreateHash(): ");
    writeFunc(
#endif
        CryptCreateHash(*prov, CALG_MD5, 0, 0, hash)
#ifndef DEBUG
        ;
#endif
#ifdef DEBUG
    );
#endif
 
#ifdef DEBUG
    printf("CryptHashData(): ");
    writeFunc(
#endif
        CryptHashData(*hash, (byte*)trueSecret, strlen(secret), 0)
#ifndef DEBUG
        ;
#endif
#ifdef DEBUG
    );
#endif
 
#ifdef DEBUG
    printf("CryptDeriveKey(): ");
    writeFunc(
#endif
        CryptDeriveKey(*prov, CALG_RC4, *hash, CRYPT_EXPORTABLE, key)
#ifndef DEBUG
        ;
#endif
#ifdef DEBUG
    );
#endif
    free(trueSecret);
}
 
void inputData(char* secret, char* msg) {
    printf("Введите секретные данные: ");
    scanf("%s", secret);
    printf("\n");
    printf("Введите строку для шифрования: ");
    scanf("%s", msg);
    printf("\n");
}
 
char* readDataFromFile(char* filepath) {
    using namespace std;
    char* data;
    int cnt = 0;
    int counter = 0;
    char symbol;
    string line;
    string buffer;
 
    ifstream ifs(filepath);
    while (getline(ifs, line)) {
        if(counter > 0)
            buffer.append("\n");
        buffer.append(line);
    }
    ifs.close();
#ifdef DEBUG_READ
    cout << "buffer: " << buffer << endl;
#endif
    data = (char*)malloc(buffer.length() + 1);
    for (int i = 0; i < buffer.length(); i++) {
        data[i] = buffer[i];
    }
    data[buffer.length()] = '\0';
#ifdef DEBUG_READ
    printf("\nДанные в файле: %s\nДлина файла: %d (%d)\n", data, strlen(data), buffer.length());
#endif
 
 
    return data;
}
 
void writeStringToFile(char* data, char* filepath) {
#ifdef DEBUG_READ
    std::cout << strlen(data) << std::endl;
#endif
    std::ofstream write;
 
    write.open(filepath);
    write << data;
 
    write.close();
}
 
void inputSecret(char* secret) {
    printf("Введите секретные данные: ");
    scanf("%s", secret);
    printf("\n");
}
