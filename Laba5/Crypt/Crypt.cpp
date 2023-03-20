#include "Cryptolib.h"

//#define DEBUG
// C:\C++\lr5.txt

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTPROV prov;
    HCRYPTKEY seans;
    HCRYPTKEY openKey;
    bool res;
    byte* userData;
    byte* keyData;
    byte* cutKeydata;
    DWORD keyLen;
    DWORD dataLen;
    char* filepath = (char*)malloc(100);

    res = CryptAcquireContext(&prov, TEXT(DEFAULT_CONTAINER), NULL, PROV_RSA_FULL, CRYPT_SILENT);
    printf("----------Зашифрование----------\n\n");
    if (!res)
        printf("Error in CryptAcquireContext(): %X\n", GetLastError());

    res = CryptGetUserKey(prov, AT_KEYEXCHANGE, &openKey);
    if (!res)
        printf("Error in CryptGetUserKey(): %X\n", GetLastError());

    userData = userInput();

    dataLen = strlen((char*)userData);

#ifdef DEBUG
    printf("Данные: \n%s\n", (char*)userData);
#endif

    res = CryptGenKey(prov, CALG_RC4, CRYPT_EXPORTABLE, &seans);
    if (!res)
        printf("Error in CryptGenKey(): %X\n", GetLastError());

    res = CryptEncrypt(seans, 0, 1, 0, userData, &dataLen, dataLen);

#ifdef DEBUG
    printf("session: %X\n", seans);
#endif

    if (!res) {
        printf("Error in CryptEncrypt(): %X\n", GetLastError());
        printf("dataLen: %d\n", dataLen);
    }

#ifdef DEBUG
    printf("Зашифрованное сообщение: \n%s\n", userData);
#endif

    res = CryptExportKey(seans, openKey, SIMPLEBLOB, 0, NULL, &keyLen);
    if (!res) {
        printf("Error in CryptExportKey(): %X\n", GetLastError());
        printf("dataLen: %d\n", keyLen);
    }
    keyData = (byte*)malloc(keyLen);
    res = CryptExportKey(seans, openKey, SIMPLEBLOB, 0, keyData, &keyLen);
    if (!res) {
        printf("Error in CryptExportKey(): %X\n", GetLastError());
        printf("dataLen: %d\n", keyLen);
    }
    cutKeydata = (byte*)malloc(keyLen - 12);
    for (int i = 12; i < keyLen; i++) {
        cutKeydata[i - 12] = keyData[i];
    }

#ifdef DEBUG
    printf("Зашифрованный ключ: \n");
    printBytes(keyData, keyLen);
#endif

    printf("Введите путь до файла, куда нужно записать ключ: ");
    scanf("%s", filepath);
    printf("\n");
    writeDataToFile(keyData, keyLen, filepath);

    printf("Введите путь до файла, куда нужно записать зашифрованные данные: ");
    scanf("%s", filepath);
    printf("\n");
    writeDataToFile(userData, dataLen, filepath);

    NTE_BAD_KEY;

    system("pause");
}