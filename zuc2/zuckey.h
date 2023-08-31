#ifndef ZUC_KEY_INT
#define ZUC_KEY_INT
typedef unsigned char Byte;        //c语言没有字节类型

	typedef enum bool              //c语言没有bool类型，c99新增了_bool,但不习惯-_ -,理解一下
	{
		false,true
	}bool;

	typedef struct ZUC_DATA
	{
		unsigned int s[16];
		unsigned int x[4];                     
		unsigned int w[2];
		unsigned int r[2];
	}ZUC_DATA;

	unsigned int zuc_getKey(ZUC_DATA* data);
	bool zuc_loadKey(ZUC_DATA* data, const Byte k[], const Byte iv[]);

#endif // !ZUCKEY
