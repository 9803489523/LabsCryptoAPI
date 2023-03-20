#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>

/*
    ������� ��� �������, ������� ��������� ���������� ������������� �������
*/
void writeFunc(bool func);

/*
    ���������� ����� ��� ���������� � �����������
*/
void deriveKey(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret
);

/*
    ������� ������
*/
PBYTE encrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* msg
);

/*
    �������������� ������
*/
PBYTE decrypt(HCRYPTPROV* prov,
    HCRYPTHASH* hash,
    HCRYPTKEY* key,
    char* secret,
    char* encrypt
);

/*
    ������� ��� ����� ��� ��������� ������, ��� � ������ ��� ����������
*/
void inputData(char* secret, char* msg);

/*
    ������� ��� ������ ������ �� ����� � ������ �� � ������
*/
char* readDataFromFile(char* filepath);

/*
    ������� ��� ������ ������ � ����
*/
void writeStringToFile(char* data, char* filepath);

/*
    ������� ����� ���������� ������ ��� ����������/�������������
*/
void inputSecret(char* secret);