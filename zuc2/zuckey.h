#ifndef ZUC_KEY_INT
#define ZUC_KEY_INT
typedef unsigned char Byte;        //c����û���ֽ�����

	typedef enum bool              //c����û��bool���ͣ�c99������_bool,����ϰ��-_ -,���һ��
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
