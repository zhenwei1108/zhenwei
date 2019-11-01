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
 * algorithm��������Կ�����ͣ�һ��ӦΪ��RSA����<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * <p>
 * 2. ��ʼ������������<br>
 * 2.1 �����ⲿ��Կ��ʼ��<br>
 * initialize(keysize)<br>
 * ��ʼ����Կ��������<br>
 * ����˵����<br>
 * keysize��ָ��������Կ�ĳ��ȣ�һ��Ϊ1024����2048<br>
 * kpg.initialize(keylength);<br>
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
 * transformation��ת�������ƣ�һ���ʽ����RSA/ECB/PKCS5Padding����RSA/ECB/PKCS5NoPadding��<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * 3.2 ��ʼ��Cipher����<br>
 * init(mode,key)<br>
 * ��ʼ��Cipher��Ķ���<br>
 * ����˵����<br>
 * mode������Ĳ���ģʽ��һ��ΪCipher.PUBLIC_KEY��Cipher.PRIVATE_KEY��Cipher.ENCRYPT_MODE��Cipher.DECRYPT_MODE<br>
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
 * transformation��ת�������ƣ�һ���ʽ����RSA/ECB/PKCS5Padding����RSA/ECB/PKCS5NoPadding��<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * 4.2 ��ʼ��Cipher����<br>
 * init(mode,key)<br>
 * ��ʼ��Cipher��Ķ���<br>
 * ����˵����<br>
 * mode������Ĳ���ģʽ��һ��ΪCipher.PUBLIC_KEY��Cipher.PRIVATE_KEY��Cipher.ENCRYPT_MODE��Cipher.DECRYPT_MODE<br>
 * key��������Ӧ�Ĺ�˽Կ<br>
 * 4.3 ������<br>
 * doFinal(content)<br>
 * ͨ�����ö�content�е����ݽ��н��ܡ�<br>
 * ����ֵ�����ܺ�Ľ����<br>
 *
 */
public class TestRSAEncDecFunc {
	
	public static void main(String[] args) {
		Security.addProvider(new SwxaProvider());
		while (true) {
			int choice = -1;
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("++++++++++++++++++++++ SwxaJCE API RSA Encryption Func Test +++++++++++++++++++++");
			System.out.println("                                                                                 ");
			System.out.println(" 1 RSA External Padding Cryption Test      2 RSA External NoPadding Cryption Test");
			System.out.println(" 3 RSA Internal Padding Cryption Test                                            ");
			System.out.println("                                                                                 ");
			System.out.println(" 0 Return to Prev Menu                                                           ");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			choice = InUtil.getInput("Select:", 3);
			if (choice == 0) {
				return;
			}
			if ((choice < 1) || (choice > 3)) {
				continue;
			}

			switch (choice) {
			case 1:
				testExternalPadding();
				break;
			case 2:
				testExternalNoPadding();
				break;
			case 3:
				testInternalPadding();
				break;
			default:
				break;
			}
		}
	}

	/**
	 * �ⲿ��Կ��padding�ӽ���<br>
	 */
	public static void testExternalPadding() {
		String transformation = "RSA/ECB/PKCS1Padding";
		byte[] plain = "hello world!".getBytes();
		KeyPair kp = null;
		int keylength = -1;
		while ((keylength != 1024) && (keylength != 2048)) {
			keylength = InUtil.getInput("Please Input the Key Length (1024,2048) :", 3);
		}
		System.out.print("Create External RSA Key " + ':' + " KeyLength " + keylength + ' ' + " ... ");
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
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
		
		testExternalFn(kp, transformation, plain);
	}
	
	/**
	 * �ⲿ��Կ�ӽ���<br>
	 */
	public static void testExternalNoPadding() {
		String transformation = "RSA/ECB/NoPadding";
		KeyPair kp = null;
		int keylength = -1;
		while ((keylength != 1024) && (keylength != 2048)) {
			keylength = InUtil.getInput("Please Input the Key Length (1024,2048) :", 3);
		}
		System.out.print("Create External RSA Key " + ':' + " KeyLength " + keylength + ' ' + " ... ");
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
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
		
		testExternalFn(kp, transformation, plain);
	}
	
	/**
	 * �ڲ���Կ��padding�ӽ���
	 */
	public static void testInternalPadding() {
		String transformation = "RSA/ECB/PKCS1Padding";
		byte[] plain = "hello world!".getBytes();
		int keynum = -1;
		KeyPair kp = null;
		while ((keynum < 1) || (keynum > 100))
			keynum = InUtil.getInput("Please Input the KeyNumber (1-100) :", 3);
		System.out.print("Create Internal RSA Key " + ':' + " KeyIndex " + keynum + ' ' + " ... ");
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
			kpg.initialize(keynum << 16);
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
		
		testInternalFn(kp, transformation, plain);
	}
	
	private static void testExternalFn(KeyPair kp, String transformation, byte[] plain) {
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

	private static void testInternalFn(KeyPair kp, String transformation, byte[] plain) {
		Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(transformation, "SwxaJCE");
			cipher.init(Cipher.ENCRYPT_MODE, kp.getPrivate());
			byte[] tTemp = cipher.doFinal(plain);
			if (tTemp == null) {
				System.out.println(transformation+ " Mode Encrypt ERROR! Return value is NULL!");
			} else {
				// �������Cipher�����
				cipher = Cipher.getInstance(transformation, "SwxaJCE");
				// ��ʼ��Cipher�����
				cipher.init(Cipher.DECRYPT_MODE, kp.getPublic());
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
