/*
    Шифрование и дешифрование по симметричной схеме
*/
#include "Encryption.h"

//#define ENCRYPT
//defaultFilepath E:\C\c++\crypt.txt


int main()
{
    setlocale(LC_ALL, "rus");
    char* secret;
    char* msg;
    char* readBuff;
    PBYTE encryptBuff;
    PBYTE decryptBuff;
    HCRYPTPROV prov;
    HCRYPTHASH hash;
    HCRYPTKEY key;

    secret = (char*)malloc(100);
    char* filepath = (char*)malloc(100);

#ifdef ENCRYPT
    printf("Введите путь к файлу с открытыми данными: ");
    scanf("%s", filepath);
    msg = readDataFromFile(filepath);
    inputSecret(secret);

    encryptBuff = encrypt(&prov, &hash, &key, secret, msg);
    std::cout << "\nЗашифрованное сообщение: " << encryptBuff << "\n\n";

    writeStringToFile((char*)encryptBuff, filepath);
    free(msg);
#endif

#ifndef ENCRYPT
    printf("Введите путь к файлу с зашифрованными данными: ");
    scanf("%s", filepath);
    readBuff = readDataFromFile(filepath);
    inputSecret(secret);

    decryptBuff = decrypt(&prov, &hash, &key, secret, readBuff);
    std::cout << "\nРасшифрованное сообщение: " << decryptBuff << "\n\n";
#endif

    CryptReleaseContext(prov, 0);
    CryptDestroyHash(hash);
    CryptDestroyKey(key);
    free(secret);
    free(filepath);

    system("pause");
}
