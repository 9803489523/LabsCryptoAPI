#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <Windows.h>
#include <Wincrypt.h>
#include <stdlib.h>

typedef struct {
    char* provFullName;
    wchar_t* provPsevdonim;
    int provType;
} Provider;

void getProviders(Provider* providers, int* len);

void printProvider(Provider provider);

void menuCryptoProviders(Provider* providers, Provider* provider, int len);

void containerFillIn(LPCWSTR ñontainer);

void addCryptContainer(Provider provider);