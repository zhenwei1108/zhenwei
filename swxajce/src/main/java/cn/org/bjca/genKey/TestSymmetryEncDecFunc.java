package cn.org.bjca.genKey;

import cn.org.bjca.util.InUtil;
import com.sansec.jce.provider.SwxaProvider;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.Security;

public class TestSymmetryEncDecFunc {
	
	public static void main(String[] args) {
		Security.addProvider(new SwxaProvider());
		while (true) {
			int choice = -1;
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("++++++++++++++++++++++ SwxaJCE API RSA Encryption Func Test +++++++++++++++++++++");
			System.out.println("                                                                                 ");
			System.out.println(" 1 DES                                                                           ");
			System.out.println(" 2 3DES                                                                          ");
			System.out.println(" 3 AES                                                                           ");
			System.out.println(" 4 SM1                                                                           ");
			System.out.println(" 5 SSF33                                                                         ");
			System.out.println(" 6 SM4                                                                           ");
			System.out.println("                                                                                 ");
			System.out.println(" 0 Return to Prev Menu                                                           ");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			choice = InUtil.getSelect();
			if (choice == 0) {
				return;
			}
			if ((choice < 1) || (choice > 6)) {
				continue;
			}

			switch (choice) {
			case 1:
				DESTest.run();
				break;
			case 2:
				DES3Test.run();
				break;
			case 3:
				AESTest.run();
				break;
			case 4:
				SM1Test.run();
				break;
			case 5:
				SSF33Test.run();
				break;
			case 6:
				SM4Test.run();
				break;
			default:
				break;
			}
		}
	}

	/**
	 * �ⲿ��Կ���ӽ���<br>
	 */
	public static void testExternal(String alg, String mode, String padding) {
		String transformation = alg+"/"+mode+"/"+padding;
		byte[] plain = "hello world!".getBytes();
		Key key = null;
		int keylength = -1;
		keylength = InUtil.createSymmetryKeySize();
		
		System.out.print("Create External "+alg+" Key " + ':' + " KeyLength[" + keylength + "] ... ");
		try {
			KeyGenerator kg = KeyGenerator.getInstance(alg, "SwxaJCE");
			kg.init(keylength);
			key = kg.generateKey();
			if (key == null) {
				System.err.println("fail��");
			} else {
				// ������Կ�ɹ���
				System.out.println("ok��");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		plain = InUtil.getBytes("1234567812345678");
		
		test(key, transformation, plain);
	}
	
	
	/**
	 * �ڲ���Կ�ӽ���<br>
	 */
	public static void testInternal(String alg, String mode, String padding) {
		String transformation = alg+"/"+mode+"/"+padding;
		byte[] plain = "hello world!".getBytes();
		Key key = null;
		int keylength = -1;
		keylength = InUtil.createSymmetryKeyIndex();
		
		System.out.print("Create External "+alg+" Key " + ':' + " KeyIndex[" + keylength + "] ... ");
		try {
			KeyGenerator kg = KeyGenerator.getInstance(alg, "SwxaJCE");
			kg.init(keylength<<16);
			key = kg.generateKey();
			if (key == null) {
				System.err.println("fail��");
			} else {
				// ������Կ�ɹ���
				System.out.println("ok��");
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		plain = InUtil.getBytes("1234567812345678");
		
		test(key, transformation, plain);
	}
	

	
	private static void test(Key key, String transformation, byte[] plain) {
		Cipher cipher = null;
		try {
			System.out.println("Plain Text: " + new String(plain));
			cipher = Cipher.getInstance(transformation, "SwxaJCE");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] tTemp = cipher.doFinal(plain);
			if (tTemp == null) {
				System.err.println(transformation+ " Mode Encrypt ERROR! Return value is NULL!");
			} else {
				System.out.println("Cipher Text: " + new BASE64Encoder().encode(tTemp));
				// �������Cipher�����
				cipher = Cipher.getInstance(transformation, "SwxaJCE");
				// ��ʼ��Cipher�����
				cipher.init(Cipher.DECRYPT_MODE, key);
				// ���ý��ܺ���
				byte[] tResult = cipher.doFinal(tTemp);

				if (tResult == null) {
					System.err.println(transformation+ " Mode Decrypt ERROR! Return value is NULL!");
				}
				// �ȽϽ��
				if (new String(plain).equals(new String(tResult))) {
					System.out.println(transformation+ " Mode Encrypt and Decrypt Success!");
				} else {
					System.err.println(transformation+ " Mode Encrypt and Decrypt ERROR!");
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	static class DESTest {
		public static void run() {
			while (true) {
				int choice = -1;
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("++++++++++++++++++++++ SwxaJCE API DES Encryption Func Test +++++++++++++++++++++");
				System.out.println("                                                                                 ");
				System.out.println(" 1 DES-ECB-NOPADDING ");
				System.out.println(" 2 DES-ECB-PKCS5PADDING ");
				System.out.println(" 3 DES-CBC-NOPADDING ");
				System.out.println(" 4 DES-CBC-PKCS5PADDING ");
				System.out.println("                                                                                 ");
				System.out.println(" 0 Return to Prev Menu                                                           ");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				choice = InUtil.getSelect();
				if (choice == 0) {
					return;
				}
				if ((choice < 1) || (choice > 8)) {
					continue;
				}

				String alg = "DES";
				switch (choice) {
				case 1:
					testExternal(alg, "ECB", "NOPADDING");
					break;
				case 2:
					testExternal(alg, "ECB", "PKCS5PADDING");
					break;
				case 3:
					testExternal(alg, "CBC", "NOPADDING");
					break;
				case 4:
					testExternal(alg, "CBC", "PKCS5PADDING");
					break;
				default:
					break;
				}
			}
		}
	}
	
	static class DES3Test {
		public static void run() {
			while (true) {
				int choice = -1;
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("++++++++++++++++++++++ SwxaJCE API DES3 Encryption Func Test +++++++++++++++++++++");
				System.out.println("                                                                                 ");
				System.out.println(" 1 DES3-ECB-NOPADDING ");
				System.out.println(" 2 DES3-ECB-PKCS5PADDING ");
				System.out.println(" 3 DES3-CBC-NOPADDING ");
				System.out.println(" 4 DES3-CBC-PKCS5PADDING ");
				System.out.println("                                                                                 ");
				System.out.println(" 0 Return to Prev Menu                                                           ");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				choice = InUtil.getSelect();
				if (choice == 0) {
					return;
				}
				if ((choice < 1) || (choice > 4)) {
					continue;
				}

				String alg = "3DES";
				switch (choice) {
				case 1:
					testExternal(alg, "ECB", "NOPADDING");
					break;
				case 2:
					testExternal(alg, "ECB", "PKCS5PADDING");
					break;
				case 3:
					testExternal(alg, "CBC", "NOPADDING");
					break;
				case 4:
					testExternal(alg, "CBC", "PKCS5PADDING");
					break;
				default:
					break;
				}
			}
		}
	}
	
	static class AESTest {
		public static void run() {
			while (true) {
				int choice = -1;
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("++++++++++++++++++++++ SwxaJCE API AES Encryption Func Test +++++++++++++++++++++");
				System.out.println("                                                                                 ");
				System.out.println(" 1 AES-ECB-NOPADDING ");
				System.out.println(" 2 AES-ECB-PKCS5PADDING ");
				System.out.println(" 3 AES-CBC-NOPADDING ");
				System.out.println(" 4 AES-CBC-PKCS5PADDING ");
				System.out.println("                                                                                 ");
				System.out.println(" 0 Return to Prev Menu                                                           ");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				choice = InUtil.getSelect();
				if (choice == 0) {
					return;
				}
				if ((choice < 1) || (choice > 4)) {
					continue;
				}

				String alg = "AES";
				switch (choice) {
				case 1:
					testExternal(alg, "ECB", "NOPADDING");
					break;
				case 2:
					testExternal(alg, "ECB", "PKCS5PADDING");
					break;
				case 3:
					testExternal(alg, "CBC", "NOPADDING");
					break;
				case 4:
					testExternal(alg, "CBC", "PKCS5PADDING");
					break;
				default:
					break;
				}
			}
		}
	}
	
	static class SM1Test {
		public static void run() {
			while (true) {
				int choice = -1;
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("++++++++++++++++++++++ SwxaJCE API SM1 Encryption Func Test +++++++++++++++++++++");
				System.out.println("                                                                                 ");
				System.out.println(" 1 SM1-ECB-NOPADDING ");
				System.out.println(" 2 SM1-ECB-PKCS5PADDING ");
				System.out.println(" 3 SM1-CBC-NOPADDING ");
				System.out.println(" 4 SM1-CBC-PKCS5PADDING ");
				System.out.println("                                                                                 ");
				System.out.println(" 0 Return to Prev Menu                                                           ");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				choice = InUtil.getSelect();
				if (choice == 0) {
					return;
				}
				if ((choice < 1) || (choice > 4)) {
					continue;
				}

				String alg = "SM1";
				switch (choice) {
				case 1:
					testExternal(alg, "ECB", "NOPADDING");
					break;
				case 2:
					testExternal(alg, "ECB", "PKCS5PADDING");
					break;
				case 3:
					testExternal(alg, "CBC", "NOPADDING");
					break;
				case 4:
					testExternal(alg, "CBC", "PKCS5PADDING");
					break;
				default:
					break;
				}
			}
		}
	}
	
	
	static class SSF33Test {
		public static void run() {
			while (true) {
				int choice = -1;
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("++++++++++++++++++++++ SwxaJCE API SSF33 Encryption Func Test +++++++++++++++++++++");
				System.out.println("                                                                                 ");
				System.out.println(" 1 SSF33-ECB-NOPADDING ");
				System.out.println(" 2 SSF33-ECB-PKCS5PADDING ");
				System.out.println(" 3 SSF33-CBC-NOPADDING ");
				System.out.println(" 4 SSF33-CBC-PKCS5PADDING ");
				System.out.println("                                                                                 ");
				System.out.println(" 0 Return to Prev Menu                                                           ");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				choice = InUtil.getSelect();
				if (choice == 0) {
					return;
				}
				if ((choice < 1) || (choice > 4)) {
					continue;
				}

				String alg = "SSF33";
				switch (choice) {
				case 1:
					testExternal(alg, "ECB", "NOPADDING");
					break;
				case 2:
					testExternal(alg, "ECB", "PKCS5PADDING");
					break;
				case 3:
					testExternal(alg, "CBC", "NOPADDING");
					break;
				case 4:
					testExternal(alg, "CBC", "PKCS5PADDING");
					break;
				default:
					break;
				}
			}
		}
	}
	
	static class SM4Test {
		public static void run() {
			while (true) {
				int choice = -1;
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("++++++++++++++++++++++ SwxaJCE API SM4 Encryption Func Test +++++++++++++++++++++");
				System.out.println("                                                                                 ");
				System.out.println(" 1 SM4-ECB-NOPADDING ");
				System.out.println(" 2 SM4-ECB-PKCS5PADDING ");
				System.out.println(" 3 SM4-CBC-NOPADDING ");
				System.out.println(" 4 SM4-CBC-PKCS5PADDING ");
				System.out.println("                                                                                 ");
				System.out.println(" 0 Return to Prev Menu                                                           ");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
				choice = InUtil.getSelect();
				if (choice == 0) {
					return;
				}
				if ((choice < 1) || (choice > 4)) {
					continue;
				}

				String alg = "SM4";
				switch (choice) {
				case 1:
					testExternal(alg, "ECB", "NOPADDING");
					break;
				case 2:
					testExternal(alg, "ECB", "PKCS5PADDING");
					break;
				case 3:
					testExternal(alg, "CBC", "NOPADDING");
					break;
				case 4:
					testExternal(alg, "CBC", "PKCS5PADDING");
					break;
				default:
					break;
				}
			}
		}
	}
}
