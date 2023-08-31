#ifndef EEA3_128
#define EEA3_128
#include "zuckey.h"

/*
@author��aidener

@tip���Ǳ�׼EEA3_128,���������������һ����EEA3_DATA,һ����EEA3_MODE.
      ������ע��LENGTH�ֶβ���bit���������ֽ���

@EEA3_INCLINATION ����ָ������ϵ��(һ����Կɢ�ȵļ��)�����ڶԳ�ʼ����Կ��ɢ�ȣ���16�ֽڣ���ȫǿ�ȼ�飬
              ���絥������ϻ�С��0.5������0.5�������Ͽɰ�ȫ�������е��ò�������ǿ��,����Ҫ��ֱ����Ϊ����

@EEA3_DATA ��Ҫ����ȫ�����ݵĴ�ȡ��ͬʱ���û�����ʹ�ö��ⴴ����EEA3_DATA,ʹ��EEA3_MODE::USE_EXTEND_DATA�������ã�
           ��ҪĿ���Ƿ�������ʹ���Լ���ȫ�����ݣ����ع�����Կ����ʹ�õ�ȫ�����Է�����λ�Ĵ���

@EEA3_MODE ָ��ʹ��ģʽ����EEA3_MODE::DEFAULĬ��, EEA3_MODE::NOT_RECORD_INTI_DATAS����¼��ʼ��������EEA3_MODE::USE_EXTEND_DATAʹ�ö�������
           ����һ�������͵ڶ����������⣬������������� | ���ӣ��� NOT_RECORD_INTI_DATAS | USE_EXTEND_DATA
		   EEA3_MODE::NOT_RECORD_INTI_DATAS���ú󽫲����¼����ĳ�ʼ�����ݣ���COUNT,BEARER��
		   ��֮����������������EEA3_DATA�в�ѯ������ĳ�ʼ������

@EEA3_EERO ���������ڼ���¼һЩ����״̬����EEA3_DATA::ERRO�ֶ�����ۣ�����ʹ��if(!EEA3_DATA^EEA3_EERO::��������)ȡ������Ϊ�û��ṩָ��
           BEARER_OUT_OF_RANGE ���ز��ʶ����5λ�綨15��Χ������ǿ����ֹ��Կ����
		   ���´���ǿ����ֹ��Կ����
		   LENGTH_VALUE_ZERO ��Ҫ�������ĳ���Ϊ0�����ڳ��򲻾��м�鳤�ȹ��ܣ����ȶ�Ӧ���ɳ���Ա�Լ������Ա���ָ��Խ��
		   UNSIFE_CK ����ȫ�����ʼ���ִ�����Ҫ�����ظ�����ɢ�ȵ�����
		   NOTINTI_EEA3  δ��ʼ����Կ����������ʹ�ü��ܺͽ��ܴ���Ӧ�ȵ���EEA3_Inti()���ټӽ���

@tip2:     ͷ�ļ�������ȫ�ֱ���EEDA_DATA EEDA_DEFAULT_DATA �� EEDA_DATA* EDATA ,���Բ�ʹ�ö���EDATAʱ����ֱ�Ӵ���NULL��
           EEA3_DATA* EDATA��ָ��ǰ���õ�EEDA_DATA������������ѯ���޸�һЩEEDA_DATA�����Թ����ԣ�Ҳ���������̻߳����Ĺ���,
		   ��Ҫ���н���̰߳�ȫ����

		   EEA3_clear()�������õ�ǰEEDA_DATA״̬��������λ�Ĵ���
		   EEA3_clear_Erro()���Կ������ô������

		   ��Լ��ܷ�ʽ��Ҫ����ʹ��^������㣬�����ڳ�ʼ�������zuc_getKey()���32λ��Կ���м���
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
//ע�⣬��ʵ�����׼���������ڼ�����洢��С��λΪ�ֽڣ�����length��λΪ�ֽڣ�����׼Ϊbit
//��ָ�����ĳ��ȣ���Ԥ�ȴ������Ŀռ䣬�䳤��������һ��
bool EEA3(const Byte M[], unsigned int length, Byte C[]);
//ע�⣬������Ҫʹ����ͬ״̬��EDATA������������ͬʱ���³�ʼ����Ϊ�����ظ���ʼ��
//Ҳ���Ե�ǰ״̬���ܣ��������������ۣ�ֻҪ����ͬ��,һ�γ�ʼ�������һֱ�ӽ��ܣ����������ݣ�
//��ϧ�䲻�߱���ͬ�����ܣ��Ժ���Կ��������Ӧ����
bool DeEEA3(const Byte C[], unsigned int length, Byte M[]);
//��յ�ǰEDATAָ��ָ���EDATA
bool EEA3_clear();
//���ô���Ϊ��
void EEA3_clear_Erro();

//��ʼ����Կ��ȫǿ�ȼ�⣨����ϵ�������Թ����в�������ǿ��
bool _check_ck_security(const Byte ck[],int length, float EEA3_INCLINATION);

#endif // !EEA3_128

