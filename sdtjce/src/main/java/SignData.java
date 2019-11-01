import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;

/**
 * @ClassName SignData
 * @Description
 * @Date 2019/9/11 15:52
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class SignData extends AbstractJavaSamplerClient {

  private static TestJni initJni;

  static {
    System.load("/home/work_svn/SJJ1410/libTestJni.so");
  }

  @Override
  public SampleResult runTest(JavaSamplerContext javaSamplerContext) {
    SampleResult result = new SampleResult();
    result.sampleStart();
    try {
      String data = "test" ;
      String test = TestJni.jmj_signData(50, data);
      result.setSuccessful(true);
    } catch (Exception e) {
      result.setSuccessful(false);
      e.printStackTrace();
    }finally {
      result.sampleEnd();
    }

    return result;
  }
}
