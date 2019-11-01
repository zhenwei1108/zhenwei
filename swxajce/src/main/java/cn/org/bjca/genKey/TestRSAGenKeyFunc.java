package cn.org.bjca.genKey;

import cn.org.bjca.util.InUtil;
import com.sansec.jce.provider.SwxaProvider;
import com.sansec.util.Debug;

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
 */
public class TestRSAGenKeyFunc {
	public static void main(String[] args) {
		Security.addProvider( new SwxaProvider());
        while(true) {
            int choice = -1;
	        System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
	        System.out.println("++++++++++++++++++ SwxaJCE API Generate RSA Keypair Func Test +++++++++++++++++++");
	        System.out.println("                                                                                 ");
	        System.out.println(" 1 Generate RSA Internal Keypair Test        2 Generate RSA External Keypair Test");
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
		System.out.print("Create Internal RSA Key " + ':' + " KeyIndex " + keynum + ' ' + " ... ");
		try {
			long t1 = System.currentTimeMillis();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
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
		int keylength = -1;
		KeyPair kp = null;
		while ((keylength != 1024) && (keylength != 2048)) {
			keylength = InUtil.getInput("Please Input the Key Length (1024,2048) :", 3);
		}
		System.out.print("Create External RSA Key " + ':' + " KeyLength " + keylength + ' ' + " ... ");
		try {
			long t1 = System.currentTimeMillis();
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
			kpg.initialize(keylength);
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
	
}
