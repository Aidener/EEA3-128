#ifndef EEA3_128
#define EEA3_128
#include "zuckey.h"

/*
@author：aidener

@tip：非标准EEA3_128,添加了两个参数，一个是EEA3_DATA,一个是EEA3_MODE.
      ！！！注意LENGTH字段并非bit数，而是字节数

@EEA3_INCLINATION 可以指定变异系数(一种秘钥散度的检测)，用于对初始化秘钥串散度（长16字节）安全强度检查，
              比如单数字组合会小于0.5，低于0.5将不被认可安全，可以行调用测试所需强度,不需要可直接令为负数

@EEA3_DATA 主要负责全局数据的存取，同时，用户可以使用额外创建的EEA3_DATA,使用EEA3_MODE::USE_EXTEND_DATA参数启用，
           主要目的是方便多进程使用自己的全局数据，不必共享秘钥产生使用的全局线性反馈移位寄存器

@EEA3_MODE 指定使用模式，有EEA3_MODE::DEFAUL默认, EEA3_MODE::NOT_RECORD_INTI_DATAS不记录初始化参数，EEA3_MODE::USE_EXTEND_DATA使用额外数据
           除第一个参数和第二参数互斥外，多个参数可以用 | 连接，如 NOT_RECORD_INTI_DATAS | USE_EXTEND_DATA
		   EEA3_MODE::NOT_RECORD_INTI_DATAS启用后将不会记录输入的初始化数据，如COUNT,BEARER等
		   反之，如果启用则可以在EEA3_DATA中查询到输入的初始化数据

@EEA3_EERO 程序运行期间会记录一些错误状态并在EEA3_DATA::ERRO字段里积累，可以使用if(!EEA3_DATA^EEA3_EERO::具体类型)取出错误，为用户提供指导
           BEARER_OUT_OF_RANGE 承载层标识超过5位界定15范围，不会强制终止秘钥产生
		   以下错误将强行终止秘钥产生
		   LENGTH_VALUE_ZERO 需要加密明文长度为0，由于程序不具有检查长度功能，长度对应将由程序员自己负责，以避免指针越界
		   UNSIFE_CK 不安全随机初始化字串，主要检查多重复，低散度的序列
		   NOTINTI_EEA3  未初始化秘钥产生器就是使用加密和解密错误，应先调用EEA3_Inti()后再加解密

@tip2:     头文件定义有全局变量EEDA_DATA EEDA_DEFAULT_DATA 和 EEDA_DATA* EDATA ,所以不使用额外EDATA时可以直接传参NULL，
           EEA3_DATA* EDATA会指向当前所用的EEDA_DATA，可以用来查询和修改一些EEDA_DATA数据以供调试，也可用作多线程环境的共享,
		   需要自行解决线程安全问题

		   EEA3_clear()可以重置当前EEDA_DATA状态，包括移位寄存器
		   EEA3_clear_Erro()可以快速重置错误积累

		   如对加密方式有要求不想使用^亦或运算，可以在初始化后调用zuc_getKey()获得32位秘钥自行加密
*/
typedef struct EEA3_DATA
{
	ZUC_DATA data;
	unsigned int COUNT;
	unsigned int BEARER;
	bool DIRECTION;
	Byte CK[16];
	unsigned int LENGTH;
	unsigned int ERRO;
}EEA3_DATA ;

extern EEA3_DATA EEA3_DEFAULT_DATA;
extern EEA3_DATA* EDATA;

typedef enum EEA3_MODE
{
	DEFAULT = 1,
	NOT_RECORD_INTI_DATAS = 2,
	USE_EXTEND_DATA = 4
}EEA3_MODE;

typedef enum EEA3_EERO
{
	BEARER_OUT_OF_RANGE = 1,
	LENGTH_VALUE_ZERO = 2,
	UNSECURE_CK = 4,
	NOTINTI_EEA3 = 8,
}EEA3_EERO;

bool EEA3_INIT(unsigned int count, unsigned int bearer, const Byte ck[],
	bool direction,float EEA3_INCLINATION, EEA3_DATA* Edata, EEA3_MODE MODE);
//注意，本实现与标准的区别，由于计算机存储最小单位为字节，所以length单位为字节，而标准为bit
//请指明明文长度，请预先创建密文空间，其长度与明文一致
bool EEA3(const Byte M[], unsigned int length, Byte C[]);
//注意，解密需要使用相同状态的EDATA，可以在两端同时重新初始化，为避免重复初始化
//也可以当前状态加密，按照流密码理论，只要两边同步,一次初始化后可以一直加解密，传输多次数据，
//可惜其不具备自同步功能，以后可以考虑提出对应方案
bool DeEEA3(const Byte C[], unsigned int length, Byte M[]);
//清空当前EDATA指针指向的EDATA
bool EEA3_clear();
//重置错误为空
void EEA3_clear_Erro();

//初始化秘钥安全强度检测（变异系数），以供自行测试所需强度
bool _check_ck_security(const Byte ck[],int length, float EEA3_INCLINATION);

#endif // !EEA3_128

