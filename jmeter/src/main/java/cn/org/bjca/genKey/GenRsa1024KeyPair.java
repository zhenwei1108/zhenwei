package cn.org.bjca.genKey;

import com.sansec.jce.provider.SwxaProvider;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;

/**
 * @ClassName GenRsaKeyPair
 * @Description
 * @Date 2019/9/3 16:10
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class GenRsa1024KeyPair extends AbstractJavaSamplerClient {


  @Override
  public SampleResult runTest(JavaSamplerContext javaSamplerContext) {
    if (Security.getProvider("SwxaJCE") == null) {
      Security.addProvider(new SwxaProvider("/home/caserver/swsds.ini"));
    }
    SampleResult res = new SampleResult();
    try {
      res.sampleStart();
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "SwxaJCE");
      kpg.initialize(1024);
      KeyPair keyPair = kpg.genKeyPair();
      res.setSuccessful(true);
    } catch (Exception e) {
      res.setSuccessful(false);
      e.printStackTrace();
    }finally {
      res.sampleEnd();
    }
    return res;
  }
}
