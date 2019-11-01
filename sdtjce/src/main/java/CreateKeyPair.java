import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;

/**
 * @ClassName CreateKeyPair
 * @Description
 * @Date 2019/9/11 15:42
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class CreateKeyPair extends AbstractJavaSamplerClient {

  private static TestJni initJni = null;

  static {
    System.load("/home/work_svn/SJJ1410/libTestJni.so");
  }


  @Override
  public SampleResult runTest(JavaSamplerContext javaSamplerContext) {
    SampleResult result = new SampleResult();
    result.sampleStart();
    try {
      String[] strings = TestJni.jmj_genKeyPair();
      if (strings != null && strings.length > 0) {
        result.setSuccessful(true);
      } else {
        result.setSuccessful(false);
      }
    } catch (Exception e) {
      result.setSuccessful(false);
      e.printStackTrace();
    } finally {
      result.sampleEnd();
    }
    return result;
  }
}
