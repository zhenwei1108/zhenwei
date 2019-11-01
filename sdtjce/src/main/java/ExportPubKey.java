import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;

/**
 * @ClassName ExportPubKey
 * @Description
 * @Date 2019/9/11 15:56
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ExportPubKey extends AbstractJavaSamplerClient {

  private static TestJni initJni;

  static {
    System.load("/home/work_svn/SJJ1410/libTestJni.so");
  }


  @Override
  public SampleResult runTest(JavaSamplerContext javaSamplerContext) {
    SampleResult result = new SampleResult();
    result.sampleStart();
    try {
      String s = TestJni.jmj_exportPubKey(50);
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
