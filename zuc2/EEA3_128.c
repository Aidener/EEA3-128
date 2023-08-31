
#include<string.h>
//#include<stdio.h>
#include<stdlib.h>
#include<math.h>
#include"EEA3_128.h"

EEA3_DATA EEA3_DEFAULT_DATA = { {{0},{0},{0},{0}},0,0,0,{0},0,0 };
EEA3_DATA* EDATA = 0;                                                      //全局变量定义，存全局数据




bool _check_ck_security(const Byte ck[],int length,float EEA3_INCLINATION) {
	double average = 0, sum = 0, D = 0;
	int i = 0;
	for (i = 0; i < length; i++) {
		sum += ck[i];
	}
	average = sum / 15;
	for (i = 0; i < length; i++) {
		D += (ck[i] - average) * (ck[i] - average);
	}
	D = sqrt(D) / average;                             //变异系数
	if (D > EEA3_INCLINATION)
		return true;
	else
		return false;
}



bool EEA3_INIT(unsigned int count, unsigned int bearer, const Byte ck[], bool direction, float EEA3_INCLINATION, EEA3_DATA* Edata, EEA3_MODE MODE) {
	if (MODE & USE_EXTEND_DATA) {
		if (Edata)
			return false;
		else
			EDATA = Edata;
	}
	else
		EDATA = &EEA3_DEFAULT_DATA;
	EEA3_clear();                         //初始化数据或清空数据
	if (MODE & DEFAULT) {
		EDATA->COUNT = count;
		if (bearer > 31)
			EDATA->ERRO += 1;
		EDATA->BEARER = bearer;
		EDATA->DIRECTION = direction;
		if (!_check_ck_security(ck,16,EEA3_INCLINATION)) {
			EDATA->ERRO += UNSECURE_CK;
			return false;
		}
		memcpy(EDATA->CK, ck, 16);
		
	}
	else if (MODE & NOT_RECORD_INTI_DATAS)
	{
		if (bearer > 63)
			EDATA->ERRO += 1;
		if (!_check_ck_security(ck,16, EEA3_INCLINATION)) {
			EDATA->ERRO += UNSECURE_CK;
			return false;
		}
	}
	Byte IV[16] = { 0 };
	Byte* cou = &count;
	IV[3] = cou[0];
	IV[2] = cou[1];
	IV[1] = cou[2];
	IV[0] = cou[3];
	IV[4] = (bearer << 3)|((unsigned int)direction << 2)&0xFC;
	IV[5] = IV[6] = IV[7] = 0;
	unsigned int i = 0;
	for (i = 0; i < 8; i++)
		IV[i + 8] = IV[i];
	zuc_loadKey(&EDATA->data, EDATA->CK, IV);
	return true;
}

bool EEA3(const Byte M[], unsigned int length, Byte C[]) {
	if (!EDATA) {
		EEA3_DEFAULT_DATA.ERRO += NOTINTI_EEA3;
		return false;
	}
	if (!length) {
		EDATA->ERRO += LENGTH_VALUE_ZERO;
		return false;
	}
	EDATA->LENGTH = length;
	unsigned int i = 0,j=0;
	unsigned int w = zuc_getKey(&(EDATA->data));
	Byte* k = NULL;
	for (i = 0; i < EDATA->LENGTH / 4; i++) {
		w = zuc_getKey(&(EDATA->data));
		k = &w;
		for (j = 0; j < 4; j++)
			C[4 * i + j] = M[4 * i + j] ^ k[3 - j];
	}
	unsigned int rem = EDATA->LENGTH % 4;
	if (rem) {
		w = zuc_getKey(&(EDATA->data));
		k = &w;
		for (j = 0; j < rem; j++)
			C[EDATA->LENGTH - rem + j] = k[3-j] ^ M[EDATA->LENGTH - rem + j];
	}
	return true;
}

bool DeEEA3(const Byte C[], unsigned int length, Byte M[]) {
	if (!EDATA) {
		EEA3_DEFAULT_DATA.ERRO += NOTINTI_EEA3;
		return false;
	}
	if (!length) {
		EDATA->ERRO += LENGTH_VALUE_ZERO;
		return false;
	}
	EDATA->LENGTH = length;
	unsigned int i = 0, j = 0;
	unsigned int w = zuc_getKey(&(EDATA->data));
	Byte* k = NULL;
	for (i = 0; i < EDATA->LENGTH / 4; i++) {
		w = zuc_getKey(&(EDATA->data));
		k = &w;
		for (j = 0; j < 4; j++)
			M[4 * i + j] = C[4 * i + j] ^ k[3 - j];
	}
	unsigned int rem = EDATA->LENGTH % 4;
	if (rem) {
		w = zuc_getKey(&(EDATA->data));
		k = &w;
		for (j = 0; j < rem; j++)
			M[EDATA->LENGTH  - rem + j] = k[3 - j] ^ C[EDATA->LENGTH - rem + j];
	}
	return true;
}


bool EEA3_clear()
{
	EDATA->data.r[0] = 0;
	EDATA->data.r[1] = 0;
	EDATA->data.w[0] = 0;
	EDATA->data.w[1] = 0;
	int i = 0;
	for (i = 0; i < 4; i++) {
		EDATA->data.x[i] = 0;
	}
	for ( i = 0; i < 16; i++)
	{
		EDATA->data.s[i] = 0;
		EDATA->CK[i] = 0;
	}
	EDATA->LENGTH = 0;
	EDATA->DIRECTION = false;
	EDATA->BEARER = 0;
	EDATA->COUNT = 0;
	EDATA->ERRO = 0;
	return true;
}


void EEA3_clear_Erro()
{
	EDATA->ERRO = 0;
}

