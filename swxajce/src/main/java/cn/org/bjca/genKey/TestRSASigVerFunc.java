package cn.org.bjca.genKey;

import cn.org.bjca.util.InUtil;
import com.sansec.jce.provider.SwxaProvider;
import sun.misc.BASE64Encoder;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
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
 * 3. ǩ��<br>
 * 3.1 �õ�Signature����<br>
 * Signature.getInstance(algorithm, provider);<br>
 * ����Signature��Ķ�������ָ�����ܵ�ģʽ���ṩ�����ơ�<br>
 * ����˵����<br>
 * algorithm��ǩ����ժҪ�㷨��һ���ʽ����SHA1WithRSA������SHA224WithRSA������SHA256WithRSA������SHA384WithRSA������SHA512WithRSA������SHA1/RSA��<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * 3.2 ��ʼ��Signature����
 * initSign(privateKey);
 * ����˵����<br>
 * privateKey�� ǩ����˽Կ<br>
 * 3.3 ����Ҫǩ��������<br>
 * update(data);<br>
 * ����˵����<br>
 * data�� Ҫǩ��������<br>
 * 3.4 ������<br>
 * sign()<br>
 * ����ֵ�����ܺ�Ľ����<br>
 * <p>
 * 4. ��ǩ<br>
 * 4.1 �õ�Signature����<br>
 * Signature.getInstance(algorithm, provider);<br>
 * ����Signature��Ķ�������ָ�����ܵ�ģʽ���ṩ�����ơ�<br>
 * ����˵����<br>
 * algorithm��ǩ����ժҪ�㷨��һ���ʽ����SHA1WithRSA������SHA224WithRSA������SHA256WithRSA������SHA384WithRSA������SHA512WithRSA������SHA1/RSA��<br>
 * provider��JCE�ṩ�ߵ����֣�һ��ӦΪ����SwxaJCE��<br>
 * 4.2 ��ʼ��Signature����<br>
 * initVerify(publicKey);<br>
 * ����˵����<br>
 * publicKey����ǩ�Ĺ�Կ<br>
 * 4.3 ��������<br>
 * update(data);<br>
 * ����˵����<br>
 * data�� Ҫ��ǩ������<br>
 * 4.4 ������<br>
 * verify(signature);<br>
 * ����˵����<br>
 * signature��ǩ��ֵ<br>
 * ����ֵ����ǩ�Ľ����<br>
 */
public class TestRSASigVerFunc {
	

	public static void main(String[] args) {
		Security.addProvider( new SwxaProvider());
		while (true) {
			int choice = -1;
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("+++++++++++++++++++++++++ SwxaJCE API RSA Sign Func Test ++++++++++++++++++++++++");
			System.out.println("                                                                                 ");
			System.out.println(" 1 RSA Internal Sign And Verify Test          2 RSA External Sign And Verify Test");
			System.out.println("                                                                                 ");
			System.out.println(" 0 Return to Prev Menu                                                           ");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			choice = InUtil.getInput("Select:", 3);
			if (choice == 0) {
				return;
			}
			if ((choice < 1) || (choice > 2)) {
				continue;
			}

			switch (choice) {
			case 1:
				testInternalSign();
				break;
			case 2:
				testExternalSign();
				break;
			default:
				break;
			}
		}
	}


	private static void testSign(KeyPair kp) {
		PrivateKey privateKey = kp.getPrivate();
		PublicKey publicKey = kp.getPublic();
		Signature signatue = null;
		byte[] out;
		byte[] dataInput = "��23132hello1231223".getBytes();
		List<String> alg = new ArrayList<String>();
		alg.add("SHA1WithRSA");
		alg.add("SHA224WithRSA");
		alg.add("SHA256WithRSA");
		alg.add("SHA384WithRSA");
		alg.add("SHA512WithRSA");
		alg.add("SHA1/RSA");
		System.out.println("Source Data : " + new String(dataInput));
		try {
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
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	/**
	 * �ڲ���Կǩ����ǩ<br>
	 */
	public static void testInternalSign() {
		KeyPair kp = TestRSAGenKeyFunc.testGenInternalKey();
		testSign(kp);
	}
	
	/**
	 * �ⲿ��Կǩ����ǩ<br>
	 */
	public static void testExternalSign() {
		KeyPair kp = TestRSAGenKeyFunc.testGenExternalKey();
		testSign(kp);
	}
}
