package cn.org.bjca.genKey;

import com.sansec.jce.provider.SwxaProvider;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

public class Demo {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new SwxaProvider());
		System.out.println("random demo          =======================");
		testRandom();
		System.out.println("gen rsa keypair demo =======================");
		testGenRSAKey();
		System.out.println("rsa cipher demo      =======================");
		testRSACipher();
		System.out.println("rsa sign demo        =======================");
		testRSASign();
		System.out.println("gen sm2 keypair demo =======================");
		testGenSM2Key();
		System.out.println("sm2 cipher demo      =======================");
		testSM2Cipher();
		System.out.println("sm2 sign demo        =======================");
		testSM2Sign();
		System.out.println("sm1 cipher demo      =======================");
		testSM1Cipher();
	}
	public static void testRandom() throws Exception {
		SecureRandom random = SecureRandom.getInstance("RND", "SwxaJCE");
		int length = random.nextInt(819);
		//������������󳤶�Ϊ 8kB(8192B)
		byte[] tmp = random.generateSeed(length);
		System.out.println(new BASE64Encoder().encode(tmp));
	}
	
	public static KeyPair testGenRSAKey() throws Exception {
		KeyPair kp = null;
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
		//int keysize = 1024�� 2048�� 3072�� 4096�� n<<16(nΪ��Կ��ţ�
		/*
		// ��ʼ������1024������Կ
		int keysize = 1024; 
		kpg.initialize(keysize);
		*/
		/*
		// ��ʼ�����������1����Կ
		int keysize = 1<<16; 
		kpg.initialize(keysize);
		 */
		// ��ʼ�����������2����Կ
		kpg.initialize(2<<16);
		
		kp = kpg.genKeyPair();
		if (kp == null) {
			System.out.println("����RSA��Կ��ʧ�ܣ�");
		} else {
			// ������Կ�ɹ���
			System.out.println(kp.getPublic());
			System.out.println(kp.getPrivate());
		}
		
		return kp;
	}
	
	public static void testRSACipher() throws Exception {
		// ����RSA��Կ��
		KeyPair kp = testGenRSAKey();
		String transformation = "";
		byte[] plain = "hello".getBytes();
		Cipher cipher = null;
		/*
		 // ��transformation = "RSA/ECB/NoPadding" ģʽ��ʼ���õ���Cipher���� ����ǰ�󶼲�����������������Ҫ���������ݲ�����ģ�����������
		 cipher = Cipher.getInstance("RSA/ECB/NoPadding", "SwxaJCE");
		 */
		// ��transformation = "RSA/ECB/PKCS1Padding"ģʽ��ʼ���õ���Cipher���� ��������ǰ��������PKCS1 padding ���������Լ��ܳ�������unpadding
		transformation = "RSA/ECB/PKCS1Padding";
		//long t1 = System.currentTimeMillis();
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
	}
	
	public static void testRSASign() throws Exception {
		// ����RSA��Կ��
		KeyPair kp = testGenRSAKey();
		PrivateKey privateKey = kp.getPrivate();
		PublicKey publicKey = kp.getPublic();
		Signature signatue = null;
		byte[] out;
		byte[] dataInput = "������δ�Ű�".getBytes();
		List<String> alg = new ArrayList<String>();
		/**
		 * RSAǩ���㷨֧�� SHA1��SHA224��SHA256��SHA384��SHA512��MD2��MD4��MD5
		 */
		alg.add("SHA1WithRSA");		//SHA1
		alg.add("SHA1/RSA");		//SHA1
		alg.add("SHA224WithRSA");	//SHA224
		alg.add("SHA256WithRSA");	//SHA256
		alg.add("SHA384WithRSA");	//SHA384
		alg.add("SHA512WithRSA");	//SHA512
		alg.add("MD2WithRSA");		//MD2
		alg.add("MD4WithRSA");		//MD4
		alg.add("MD5WithRSA");		//MD5
		System.out.println("Source Data : " + new String(dataInput));
		for(int i=0; i<alg.size(); i++) {
			System.out.println("Sign Algorithm [ "+alg.get(i)+" ]");
			signatue = Signature.getInstance(alg.get(i), "SwxaJCE");
			//ǩ��
			signatue.initSign(privateKey);
			signatue.update(dataInput);
			out = signatue.sign();
			System.out.println("Sign Value : "+new BASE64Encoder().encode(out));
			//��ǩ
			signatue.initVerify(publicKey);
			signatue.update(dataInput);
			boolean flag = signatue.verify(out);
			
			System.out.println("Verify Result: "+flag);
			System.out.println();
		}
	}
	
	public static KeyPair testGenSM2Key() throws Exception {
		KeyPair kp = null;
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SwxaJCE");
		//int keysize = 256�� n<<16(nΪ��Կ��ţ�
		/*
		// ��ʼ������256������Կ
		int keysize = 256; 
		kpg.initialize(keysize);
		*/
		/*
		// ��ʼ�����������1����Կ
		int keysize = 1<<16; 
		kpg.initialize(keysize);
		 */
		
		// ��ʼ�����������2����Կ
		kpg.initialize(2<<16);
		
		kp = kpg.genKeyPair();
		if (kp == null) {
			System.out.println("����SM2��Կ��ʧ�ܣ�");
		} else {
			// ������Կ�ɹ���
			System.out.println(kp.getPublic());
			System.out.println(kp.getPrivate());
		}
		
		return kp;
	}
	
	public static void testSM2Cipher() throws Exception {
		// ����SM2��Կ��
		KeyPair kp = testGenSM2Key();
		String transformation = "";
		byte[] plain = "hello".getBytes();
		Cipher cipher = null;
		// ��transformation = "SM2"ģʽ��ʼ���õ���Cipher���� ��SM2�ӽ���������������Ϊ����SM2Ӧ�ù淶�е����Ļ���
		transformation = "SM2";
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
	}
	
	public static void testSM2Sign() throws Exception {
		// ����SM2��Կ��
		KeyPair kp = testGenSM2Key();
		PrivateKey privateKey = kp.getPrivate();
		PublicKey publicKey = kp.getPublic();
		Signature signature = null;
		byte[] out;
		byte[] dataInput = "������δ�Ű�".getBytes();
		List<String> alg = new ArrayList<String>();
		/**
		 * SM2ǩ���㷨֧�� SHA1��SHA224��SHA256��SM3
		 */
		alg.add("SHA1WithSM2");		//SHA1
		alg.add("SHA1/SM2");		//SHA1
		alg.add("SHA224WithSM2");	//SHA224
		alg.add("SHA256WithSM2");	//SHA256
		alg.add("SM3WithSM2");		//SM3

		System.out.println("Source Data : " + new String(dataInput));
		for(int i=0; i<alg.size(); i++) {
			System.out.println("Sign Algorithm [ "+alg.get(i)+" ]");
			signature = Signature.getInstance(alg.get(i), "SwxaJCE");
			//ǩ��
			signature.initSign(privateKey);
			signature.update(dataInput);
			out = signature.sign();
			//PrintUtil.printWithHex(out);
			System.out.println("Sign Value : "+new BASE64Encoder().encode(out));

			//��ǩ
			signature.initVerify(publicKey);
			signature.update(dataInput);
			boolean flag = signature.verify(out);
			
			System.out.println("Verify Result: "+flag);
			System.out.println();
		}
	}
	
	
	public static void testSM1Cipher() throws Exception {
		// ����SM1��Կ
		KeyGenerator kg = KeyGenerator.getInstance("SM1", "SwxaJCE");
		//int keysize = 128�� n<<16(nΪ��Կ��ţ�
		/*
		// ��ʼ������128������Կ
		int keysize = 128; 
		kpg.initialize(keysize);
		*/
		/*
		// ��ʼ�����������1����Կ
		int keysize = 1<<16; 
		kpg.initialize(keysize);
		 */
	
		// ��ʼ�����������1����Կ
		kg.init(1<<16);
		SecretKey key = kg.generateKey();
		String transformation = "";
		byte[] plain = "hello".getBytes();
		Cipher cipher = null;
		// ��transformation = "SM1/ECB/PKCS5Padding"ģʽ��ʼ���õ���Cipher���� ��������ǰ��������PKCS5 padding(�������һ������ȱ���������պú��ʲ����鳤��16) ���������Լ��ܳ�������unpadding
		// ֧��ECB��CBC
		transformation = "SM1/CBC/PKCS5Padding";
		cipher = Cipher.getInstance(transformation, "SwxaJCE");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] cipherText = cipher.doFinal(plain);
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] tResult = cipher.doFinal(cipherText);
		if (tResult == null) {
			System.out.println(transformation+ " Mode Decrypt ERROR! Return value is NULL!");
		}
		// �ȽϽ��
		if (new String(plain).equals(new String(tResult))) {
			System.out.println(transformation+ " Mode Encrypt and Decrypt Success!");
		} else { 
			System.out.println(transformation+ " Mode Encrypt and Decrypt ERROR!");
		}
	}
}
