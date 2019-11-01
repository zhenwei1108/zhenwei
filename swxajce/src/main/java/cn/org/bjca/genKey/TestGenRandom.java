package cn.org.bjca.genKey;

import cn.org.bjca.util.InUtil;
import com.sansec.jce.provider.SwxaProvider;
import com.sansec.util.PrintUtil;

import java.security.SecureRandom;
import java.security.Security;


public class TestGenRandom {
	public static void main(String[] args) throws Exception {
		Security.addProvider( new SwxaProvider());
		SecureRandom random = SecureRandom.getInstance("RND", "SwxaJCE");
		String str = null;
		int length = -1;
		int choice = -1;
		while(true) {
			length = -1;
			choice = -1;
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("+++++++++++++++++    SwxaJCE API Generate Random Func Test    +++++++++++++++++++");
			System.out.println("                                                                                 ");
			System.out.println(" 1 Genarate Random                                                               ");
			System.out.println("                                                                                 ");
			System.out.println(" 0 Return to Prev Menu                                                           ");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			System.out.println("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++");
			choice = InUtil.getInput("Select:", 3);
			if (choice == 0) {
				return;
			}
			if ((choice != 1)) {
				continue;
			}

			while ((length < 0) || (length > 8192)) {
				length = InUtil.getInput("Please Input the Random Length (1-8192) :", 3);
			}
			str = PrintUtil.toHexString(random.generateSeed(length));
			System.out.println(str);
		}
	}
}
