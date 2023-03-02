/*
    Шифрование и дешифрование по симметричной схеме
*/
#define _CRT_SECURE_NO_WARNINGS 1
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>

/*
    Для вывода сообщений отладки раскомментировать
*/
#define DEBUG

/*
    Функция для отладки, выводит результат выполнения промежуточных функций
*/
void writeFunc(bool func);

/*
    Генерирует ключи для шифрования и расшифровки
*/
void deriveKey(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret
);

/*
    Шифрует строку
*/
PBYTE encrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* msg
);

/*
    Расшифровывает строку
*/
PBYTE decrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* encrypt
);

/*
    Функция для ввода как секретных данных, так и данных для шифрования
*/
void inputData(char* secret, char* msg);

int main()
{
    setlocale(LC_ALL, "rus");
    char* secret;
    char* msg;
    PBYTE encryptBuff;
    PBYTE decryptBuff;
    HCRYPTPROV prov;
    HCRYPTHASH hash;
    HCRYPTKEY key;

    secret = (char*)malloc(1000);
    msg = (char*)malloc(1000);

    inputData(secret, msg);

    encryptBuff = encrypt(&prov, &hash, &key, secret, msg);
    std::cout << "\nЗашифрованное сообщение: " << encryptBuff << "\n\n";

    decryptBuff = decrypt(&prov, &hash, &key, secret, (char*)encryptBuff);
    std::cout << "\nРасшифрованное сообщение: " << decryptBuff << "\n\n";

    CryptReleaseContext(prov, 0);
    CryptDestroyHash(hash);
    CryptDestroyKey(key);
    free(secret);
    free(msg);

    system("pause");
}

void writeFunc(bool func) {
    std::string result;
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
    PBYTE encrypt = (PBYTE)malloc(lengthEncrypt);
    strcpy((char*)encrypt, msg);

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
    PBYTE decrypt = (PBYTE)malloc(lengthEncrypt);
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
#ifdef DEBUG
    printf("CryptAcquireContext(): ");
    writeFunc(
#endif
        CryptAcquireContext(prov, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)
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
        CryptHashData(*hash, (byte*)secret, strlen(secret), 0)
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
        CryptDeriveKey(*prov, CALG_RC4, *hash, 0, key)
#ifndef DEBUG
        ;
#endif
#ifdef DEBUG
    );
#endif
}

void inputData(char* secret, char* msg) {
    printf("Введите секретные данные: ");
    scanf("%s", secret);
    printf("\n");
    printf("Введите строку для шифрования: ");
    scanf("%s", msg);
    printf("\n");
}