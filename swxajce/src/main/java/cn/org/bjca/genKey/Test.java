package cn.org.bjca.genKey;

import com.sansec.jce.provider.SwxaProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;

/**
 * @ClassName Test
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/3/28 14:14
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class Test {

    public static void main(String[] args) {
        try {
            Security.addProvider( new SwxaProvider("D:\\swsds.ini"));
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
            kpg.initialize(1<<16);
            KeyPair keyPair = kpg.genKeyPair();
            System.out.println("公钥:"+Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            System.out.println("私钥:"+Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }


    }

}
