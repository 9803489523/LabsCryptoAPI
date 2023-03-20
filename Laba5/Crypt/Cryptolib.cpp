#include "Cryptolib.h"

void fillInContainer() {
    HCRYPTPROV prov;
    HCRYPTKEY key;

    CryptAcquireContext(&prov, TEXT(DEFAULT_CONTAINER), NULL, PROV_RSA_FULL, CRYPT_SILENT);
    CryptGenKey(prov, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &key);

    CryptDestroyKey(key);
    CryptReleaseContext(prov, 0);
}

byte* userInput() {
    char* path = (char*)malloc(100);
    printf("¬ведите путь к файлу: ");
    scanf("%s", path);
    printf("\n");
    return readDataFromFile(path);
}

void printBytes(byte* arr, int len) {
    for (int i = 0; i < len; i++) {
        printf("%c", arr[i]);
    }
    printf("\n");
}

void writeDataToFile(byte* data, DWORD dataLen, char* filepath) {
    FILE* write;
    write = fopen(filepath, "wb");
    fwrite(data, sizeof(byte), dataLen, write);
    fclose(write);
}

byte* readDataFromFile(char* filepath) {
    FILE* read;
    char symbol;
    int cnt = 0;
    char* str = (char*)malloc(10000);
    read = fopen(filepath, "rb");

    while (fscanf(read, "%c", &symbol) != EOF) {
        str[cnt++] = symbol;
    }

    byte* strReturn = (byte*)malloc(strlen(str) + 1);

    for (int i = 0; i < cnt; i++) {
        strReturn[i] = str[i];
    }
    strReturn[cnt] = '\0';
    free(str);
    return strReturn;
}