#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h> 

int main() {
    setlocale(LC_ALL, "rus");
    HCRYPTPROV hprov;
    HCRYPTKEY hkey;
    HCRYPTKEY hsign;

    CryptAcquireContext(&hprov, NULL, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    /*
        Генерация ключа и цифровой подписи
    */
    CryptGenKey(hprov, AT_KEYEXCHANGE, NULL, &hkey);
    CryptGenKey(hprov, AT_SIGNATURE, NULL, &hsign);
    /*
        Получение ключа и цифровой подписи
    */
    CryptGetUserKey(hprov, AT_KEYEXCHANGE, &hkey);
    CryptGetUserKey(hprov, AT_SIGNATURE, &hsign);

    std::cout << "Ключ: " << hkey << "\n";
    std::cout << "Цифровая подпись: " << hsign << "\n";
    /*
        Удаление ключей и контейнера
    */
    CryptDestroyKey(hkey);
    CryptDestroyKey(hsign);
    CryptReleaseContext(hprov, 0);
}
