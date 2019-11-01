package cn.org.bjca.genKey;

import cn.org.bjca.util.InUtil;
import cn.org.bjca.util.PKCS1Padding;
import com.sansec.jce.provider.SwxaProvider;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;


/**
 * 1. �ȵ���Կ������<br>
 * KeyPairGenerator.getInstance(algorithm,provider)<br>
 * ����˵����<br>
 * algorithm��������Կ�����ͣ�һ��ӦΪ��SM2����<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * <p>
 * 2. ��ʼ������������<br>
 * 2.1 �����ⲿ��Կ��ʼ��<br>
 * initialize(keysize)<br>
 * ��ʼ����Կ��������<br>
 * ����˵����<br>
 * keysize��ָ��������Կ�ĳ��ȣ�һ��Ϊ256<br>
 * kpg.initialize(keysize);<br>
 * 2.2 �����ڲ���Կ��ʼ��<br>
 * initialize(keynum<<16)<br>
 * ��ʼ����Կ��������<br>
 * ����˵����<br>
 * keynum��ָ�������ڲ���Կ����Կ��ţ�1-100<br>
 * kpg.initialize(keynum<<16);<br>
 * <p>
 * 3. ����<br>
 * 3.1 �õ�Cipher����<br>
 * Cipher.getInstance(transformation,provider)<br>
 * ����Cipher��Ķ�������ָ�����ܵ�ģʽ���ṩ�����ơ�<br>
 * ����˵����<br>
 * transformation��ת�������ƣ�һ���ʽ����SM2��<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * 3.2 ��ʼ��Cipher����<br>
 * init(mode,key)<br>
 * ��ʼ��Cipher��Ķ���<br>
 * ����˵����<br>
 * mode������Ĳ���ģʽ��һ��ΪCipher.ENCRYPT_MODE��Cipher.DECRYPT_MODE<br>
 * key��������Ӧ�Ĺ�˽Կ<br>
 * 3.3 ������<br>
 * doFinal(content)<br>
 * ͨ�����ö�content�е����ݽ��м��ܡ�<br>
 * ����ֵ�����ܺ�Ľ����<br>
 * <p>
 * 4. ����<br>
 * 4.1 �õ�Cipher����<br>
 * Cipher.getInstance(transformation,provider)<br>
 * ����Cipher��Ķ�������ָ�����ܵ�ģʽ���ṩ�����ơ�<br>
 * ����˵����<br>
 * transformation��ת�������ƣ�һ���ʽ����SM2��<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * 4.2 ��ʼ��Cipher����<br>
 * init(mode,key)<br>
 * ��ʼ��Cipher��Ķ���<br>
 * ����˵����<br>
 * mode������Ĳ���ģʽ��һ��ΪCipher.ENCRYPT_MODE��Cipher.DECRYPT_MODE<br>
 * key��������Ӧ�Ĺ�˽Կ<br>
 * 4.3 ������<br>
 * doFinal(content)<br>
 * ͨ�����ö�content�е����ݽ��н��ܡ�<br>
 * ����ֵ�����ܺ�Ľ����<br>
 *
 */
public class TestSM2EncDecFunc {
	
	public static void main(String[] args) {
		Security.addProvider( new SwxaProvider("D:\\swsds.ini"));
		while (true) {
			int choice = -1;
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("++++++++++++++++++++++ SwxaJCE API SM2 Encryption Func Test ++++++++++++++++++++++");
			System.out.println("                                                                                 ");
			System.out.println(" 1 SM2 Internal  Cryption Test            2 SM2 External Cryption Test           ");
			System.out.println("                                                                                 ");
			System.out.println(" 0 Return to Prev Menu                                                           ");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			choice = InUtil.getInput("Select:", 3);
			//choice = 1;
			if (choice == 0) {
				return;
			}
			if ((choice < 1) || (choice > 2)) {
				continue;
			}

			switch (choice) {
			case 1:
				testInternal();
				break;
			case 2:
				testExternal();
				break;
			}
		}
	}

	
	/**
	 * �ⲿ��Կ�ӽ���<br>
	 */
	public static void testExternal() {
		String transformation = "SM2";
		KeyPair kp = null;
		int keylength = 256;
		while (keylength != 256) {
			keylength = InUtil.getInput("Please Input the Key Length (256) :", 3);
		}
		System.out.print("Create External SM2 Key " + ':' + " KeyLength " + keylength + ' ' + " ... ");
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SwxaJCE");
			kpg.initialize(keylength);
			kp = kpg.genKeyPair();
			if (kp == null) {
				System.out.println("fail��");
			} else {
				// ������Կ�ɹ���
				System.out.println("ok��");
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		byte[] plain = PKCS1Padding.EncPadding("hello".getBytes(), keylength>>3);
		//plain = InUtil.getBytes(32);
		
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(transformation, "SwxaJCE");
			cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
			byte[] tTemp = cipher.doFinal(plain);
			if (tTemp == null) {
				System.out.println(transformation+ " Mode Encrypt ERROR! Return value is NULL!");
			} else {
				// �������Cipher�����
				cipher = Cipher.getInstance(transformation, "SwxaJCE");
				// ��ʼ��Cipher�����
				cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
				// ���ý��ܺ���
				byte[] tResult = cipher.doFinal(tTemp);

				if (tResult == null) {
					System.out.println(transformation+ " Mode Decrypt ERROR! Return value is NULL!");
				}
				// �ȽϽ��
				if (new String(plain).equals(new String(tResult)))
					System.out.println(transformation+ " Mode Encrypt and Decrypt Success!");
				else
					System.out.println(transformation+ " Mode Encrypt and Decrypt ERROR!");
			}
		} catch (Exception e) {
			System.out.println(transformation+ " Mode Encrypt and Decrypt ERROR!");
			e.printStackTrace();
		}
	}
	
	/**
	 * �ڲ���Կ���ӽ���
	 */
	public static void testInternal() {
		String transformation = "SM2";
		KeyPair kp = null;
		int keynum = -1;
		while ((keynum < 1) || (keynum > 100)) {
			keynum = InUtil.getInput("Please Input the KeyNumber (1-100) :", 3);
		}
		System.out.print("Create Internal SM2 Key " + ':' + " KeyIndex " + keynum + ' ' + " ... ");
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SwxaJCE");
			kpg.initialize(keynum<<16);
			kp = kpg.genKeyPair();
			if (kp == null) {
				System.out.println("fail��");
			} else {
				// ������Կ�ɹ���
				System.out.println("ok��");
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		byte[] plain = "hello world".getBytes();
	
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(transformation, "SwxaJCE");
			//System.out.println(transformation);
			cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
			byte[] tTemp = cipher.doFinal(plain);
			if (tTemp == null) {
				System.out.println(transformation+ " Mode Encrypt ERROR! Return value is NULL!");
			} else {
				// �������Cipher�����
				cipher = Cipher.getInstance(transformation, "SwxaJCE");
				// ��ʼ��Cipher�����
				cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
				// ���ý��ܺ���
				byte[] tResult = cipher.doFinal(tTemp);

				if (tResult == null) {
					System.out.println(transformation+ " Mode Decrypt ERROR! Return value is NULL!");
				}
				// �ȽϽ��
				if (new String(plain).equals(new String(tResult)))
					System.out.println(transformation+ " Mode Encrypt and Decrypt Success!");
				else
					System.out.println(transformation+ " Mode Encrypt and Decrypt ERROR!");
			}
		} catch (Exception e) {
			System.out.println(transformation+ " Mode Encrypt and Decrypt ERROR!");
			e.printStackTrace();
		}
	}
}
