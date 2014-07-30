#pragma once
#include "Windows.h"

bool DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask);

DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE *bMask, char * szMask);