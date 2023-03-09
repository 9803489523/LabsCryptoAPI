#include "ProvLib.h"


void getProviders(Provider* providers, int* len) {
    DWORD index = 0;
    DWORD type;
    LPSTR fullName;
    LPWSTR psevdonim;
    DWORD fullNameLength;
    DWORD psevdonimLength;
    while (CryptEnumProvidersA(index, NULL, 0, &type, NULL, &fullNameLength) &&
        CryptEnumProvidersW(index, NULL, 0, &type, NULL, &psevdonimLength)) {

        fullName = (LPSTR)malloc(fullNameLength);
        psevdonim = (LPWSTR)malloc(psevdonimLength);

        CryptEnumProvidersA(index, NULL, 0, &type, fullName, &fullNameLength);
        CryptEnumProvidersW(index, NULL, 0, &type, psevdonim, &psevdonimLength);

        if (len != 0) {
            providers[index].provFullName = fullName;
            providers[index].provPsevdonim = psevdonim;
            providers[index].provType = type;
        }

        index++;
    }
    *len = index;
}

void printProvider(Provider provider) {
    printf("%s, %X, %d\n", provider.provFullName, provider.provPsevdonim, provider.provType);
}

void menuCryptoProviders(Provider* providers, Provider* provider, int len) {
    int choose;
    printf("Выберите криптопровайдера из списка: \n");
    for (int i = 0; i < len; i++) {
        printf("\t%d). %s\n", i + 1, providers[i].provFullName);
    }
    scanf("%d", &choose);
    if (choose < 0 || choose > len) {
        printf("Некорректный ввод, сделайте выбор заново!");
        menuCryptoProviders(providers, provider, len);
    }
    else {
        *provider = providers[choose - 1];
    }
}

void addCryptContainer(Provider provider) {
    HCRYPTPROV prov;
    HCRYPTKEY key;
    LPCWSTR keyContainer;
    bool res;

    const TCHAR* str = (TCHAR*)malloc(100);
    printf("Введите название контейнера: ");
    wscanf(L"%s", str);
    keyContainer = (LPWSTR)str;

    res = CryptAcquireContext(&prov, keyContainer, provider.provPsevdonim, provider.provType, CRYPT_NEWKEYSET);



    if (res) {
        CryptGenKey(prov, AT_SIGNATURE, CRYPT_EXPORTABLE, &key);
        printf("Сгенерирован новый контейнер  с ключом: %X\n", str, key);
    }
    else {
        if (GetLastError() == NTE_EXISTS) {
            CryptAcquireContext(&prov, keyContainer, NULL, PROV_RSA_FULL, CRYPT_SILENT);
            CryptGetUserKey(prov, AT_SIGNATURE, &key);
            printf("Контейнер '%s' существует, извлечение ключа: %X\n", keyContainer, key);
        }
    }

    CryptDestroyKey(key);
    CryptReleaseContext(prov, 0);
}

void containerFillIn(LPCWSTR* сontainer) {
    const TCHAR* str = (TCHAR*)malloc(100);
    printf("Введите название контейнера: ");
    wscanf(L"%s", str);
    *сontainer = (LPWSTR)str;
}