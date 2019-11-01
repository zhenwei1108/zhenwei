package cn.org.bjca.genKey;

import cn.org.bjca.util.InUtil;
import com.sansec.jce.provider.SwxaProvider;
import com.sansec.util.Debug;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;

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
 */
public class TestSM2GenKeyFunc {
	public static void main(String[] args) {
		Security.addProvider( new SwxaProvider("D:\\swsds.ini"));
        while(true) {
            int choice = -1;
	        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	        System.out.println("+++++++++++++++++++ SwxaJCE API Generate SM2 Keypair Func Test +++++++++++++++++++");
	        System.out.println("                                                                                 ");
	        System.out.println(" 1 Generate SM2 Internal Keypair Test        2 Generate SM2 External Keypair Test");
	        System.out.println("                                                                                 ");
	        System.out.println(" 0 Return to Prev Menu                                                           ");
	        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	        choice = InUtil.getInput("Select:", 3);
	        if(choice == 0) {
	        	return;
	        }
	        if ((choice < 0) || (choice > 2)) {
	            continue;
	        } 
	        long t1 = 0;
	        switch (choice) {
			case 1:
				t1 = System.currentTimeMillis();
				testGenInternalKey();
				Debug.println(Debug.INFO,"Time : "+( System.currentTimeMillis()-t1));
				break;
			case 2:
				t1 = System.currentTimeMillis();
				testGenExternalKey();
				Debug.println(Debug.INFO,"Time : "+( System.currentTimeMillis()-t1));
				break;
			default:
				break;
			}
        }
	}
	
	/**
	 * �����ڲ���Կ<br>
	 */
	public static KeyPair testGenInternalKey() {
		int keynum = -1;
		KeyPair kp = null;
		while ((keynum < 1) || (keynum > 100))
			keynum = InUtil.getInput("Please Input the KeyNumber (1-100) :", 3);
		System.out.print("Create Internal SM2 Key " + ':' + " KeyIndex " + keynum + ' ' + " ... ");
		try {
			long t1 = System.currentTimeMillis();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SwxaJCE");
			kpg.initialize(keynum << 16);
			Debug.println(Debug.INFO, "Time : "+( System.currentTimeMillis()-t1));
			t1 = System.currentTimeMillis();
			kp = kpg.genKeyPair();
			Debug.println(Debug.INFO, "Time : "+( System.currentTimeMillis()-t1));
			if (kp == null) {
				System.out.println("fail��");
			} else {
				// ������Կ�ɹ���
				System.out.println("ok��");
				System.out.println(kp.getPublic());
				System.out.println(kp.getPrivate());
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		
		return kp;
	}
	
	/**
	 * �����ⲿ��Կ<br>
	 */
	public static KeyPair testGenExternalKey() {
		int keylength = 256;
		KeyPair kp = null;
		while (keylength != 256) {
			keylength = InUtil.getInput("Please Input the Key Length (256) :", 3);
		}
		System.out.print("Create External SM2 Key " + ':' + " KeyLength " + keylength + ' ' + " ... ");
		try {
			long t1 = System.currentTimeMillis();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "SwxaJCE");
			kpg.initialize(keylength);
			Debug.println(Debug.INFO, "Time : "+( System.currentTimeMillis()-t1));
			t1 = System.currentTimeMillis();
			kp = kpg.genKeyPair();
			System.out.println("私钥为:{}"+ Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
			System.out.println("公钥为:{}"+ Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));
			Debug.println(Debug.INFO, "Time : "+( System.currentTimeMillis()-t1));
			
			if (kp == null) {
				System.out.println("fail��");
			} else {
				// ������Կ�ɹ���
				System.out.println("ok��");
				System.out.println(kp.getPublic());
				System.out.println(kp.getPrivate());
			}
		} catch (Exception e) {
			System.out.println(e.getMessage());
		}
		
		return kp;
	}
	
}
