/**
 * @ClassName InitJni
 * @Description
 * @Date 2019/9/10 11:22
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class TestJni {

//  static {
//    System.loadLibrary("TestJni");
//  }

  public static native int test_a();

  public static native String test_b(int index);
  //加密机相关

  //初始化
  public static native int jmj_init();

  //sm2签名
  //@index:索引
  //@indata:原文
  //返回签名值
  public static native String jmj_signData(int index, String indata);

  //导出sm2公钥
  //@index:索引
  //返回公钥
  public static native String jmj_exportPubKey(int index);

  //产生sm2外部密钥对
  //返回密钥对
  public static native String[] jmj_genKeyPair();

  //释放
  public static native int jmj_free();


}
