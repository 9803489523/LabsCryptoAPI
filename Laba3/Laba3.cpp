#include "ProvLib.h"

#define ADD_CONTAINER

int main()
{
    setlocale(LC_ALL, "rus");

    HCRYPTPROV prov;
    Provider provGet;
    Provider* providers;
    int lenProviders;
    byte* containerName = (byte*)malloc(1000);
    DWORD containerNameLength;

    providers = (Provider*)malloc(1000);

    getProviders(providers, &lenProviders);

    menuCryptoProviders(providers, &provGet, lenProviders);

#ifdef ADD_CONTAINER
    addCryptContainer(provGet);
#endif

    CryptAcquireContext(&prov, NULL, provGet.provPsevdonim, provGet.provType, CRYPT_VERIFYCONTEXT);

    int cnt = 0;
    bool res = CryptGetProvParam(prov, PP_ENUMCONTAINERS, containerName, &containerNameLength, CRYPT_FIRST);
    if (!res) {
        int error = GetLastError();
        printf("Ошибка с кодом: %X\n", error);
        switch (error) {
            case 259:
                printf("В данном криптопровайдеры контейнеры отсутсвуют\n");
                break;
            case NTE_PERM:
                printf("Отказано в доступе\n");
                break;
            default:
                printf("Неизвестная ошибка\n");

        }
        goto stop;
    }
    printf("Список контейнеров в криптопровайдере %s\n", provGet.provFullName);
    printf("\t%d). %s\n", cnt + 1, containerName);
    while (CryptGetProvParam(prov, PP_ENUMCONTAINERS, containerName, &containerNameLength, CRYPT_NEXT)) {
        printf("\t%d). %s\n", cnt + 2, containerName);
        cnt++;
    }NTE_BAD_DATA;

stop:
    CryptReleaseContext(prov, 0);
    system("pause");
}
