import org.apache.log4j.Logger;

public class JCEDemo
{
	static Logger logger = Logger.getLogger(JCEDemo.class);
	static String certfile = "D:\\cert.cer";		//用于证书和keystore测试  
	static String p12file = "D:\\certpfx.pfx";	    //用于P12测试
	static String p7cert = "D:\\certp7.cer";		//用于P7数字信封和数字签名测试
	static String p7envfile = "D:\\envp7.p7b";	    //用于P7数字信封测试
	static String p7signfile = "D:\\signp7.p7b";	//用于P7数字签名测试

	static int certkeyid = 5;		//证书对应的密钥对
	static int cakeyid = 6 ;	    //签发证书需要的密钥对
	static boolean isRSA = true;	//true，表示以rsa为例，keybits为1024或2048；否则以SM2为例，keybits为256
	static int keybits=1024;//256;		//如果isRSA为true，keybits为1024或2048，否则为256
	
	/**
	 * 为后续的操作准备内部密钥
	 */
	public static void PrepareKey(int certkeyid,int cakeyid,boolean isRSA,int keybits){
		FMRsa rsa = new FMRsa();
		//RSA加解密和签名验签操作需要用到内部1号1024密钥和2号2048密钥
		rsa.GenerateInternalRSAKeyPair(1, 1024);
		rsa.GenerateInternalRSAKeyPair(2, 2048);
		//SM2加解密和签名验签操作需要用到内部1号和2号密钥
		FMSM2 sm2 = new FMSM2();
		sm2.GenerateInternalSM2KeyPair(1);
		sm2.GenerateInternalSM2KeyPair(2);
		
		//生成keystore时用的密钥号
		if(isRSA){
			rsa.GenerateInternalRSAKeyPair(certkeyid, keybits);
			rsa.GenerateInternalRSAKeyPair(cakeyid, keybits);
		}else{
			sm2.GenerateInternalSM2KeyPair(certkeyid);
			sm2.GenerateInternalSM2KeyPair(cakeyid);
		}
		
		//SM1加解密测试需要用到1号密钥
		FMSM1 sm1 = new FMSM1();
		sm1.GenerateInternalKey(1);
		sm1.GenerateInternalKey(1);
	}
	
	/**
	 * RSA加解密测试
	 */
	public static void FMRSAEncAndDecTest()
	{
		FMRsa rsa = new FMRsa();
		rsa.RSAEncAndDecTest();
	}
	
	/**
	 * RSA签名验签
	 */
	public static void FMRSASignAndVerifyTest()
	{
		FMRsa rsa = new FMRsa();
		rsa.RSASignAndVerifyTest();
	}
	
	/**
	 * SM2加解密测试
	 */
	public static void FMSM2EncAndDecTest()
	{
		FMSM2 sm2 = new FMSM2();
		sm2.SM2EncAndDecTest();
	}
	
	/**
	 * SM2签名验签测试
	 */
	public static void FMSM2SignAndVerifyTest()
	{
		FMSM2 sm2 = new FMSM2();
		sm2.SM2SignAndVerifyTest();
		//sm2.TestSM2Sign();
	}
	
	/**
	 * SM2密钥协商测试
	 */
	public static void FMSM2AgreementTest(){
		FMSM2 sm2 = new FMSM2();
		//sm2.agreementtest();
		sm2.agreementtestSM2_Soft();
	}
	
	/**
	 * 对称密钥加解密测试
	 */
	public static void FMSYSEncAndDecTest()
	{
		FMSYS sys = new FMSYS();
		sys.SYSEncAndDecTest();
	}
	
	/**
	 * 内部SM1密钥加解密
	 */
	public static void FMSM1EncAndDecTest()
	{
		FMSM1 sm1 = new FMSM1();
		sm1.SM1EncAndDecTest();
	}

	/**
	 * SM3withSM2测试
	 */
	public static void FMSM3WithSM2Test()
	{
		FMSM3Test sm3 = new FMSM3Test();
		sm3.SM3WithSM2Test();		
	}
	
	/**
	 * 哈希测试
	 */
	public static void FMHashTest()
	{
		FMHash hash = new FMHash();
		hash.hashTest();
	}
		
	/**
	 * HMAC测试
	 */
	public static void FMHMACTest()
	{
		FMHash hmac = new FMHash();
		hmac.HMACTest();
	}
	
	/**
	 * CMAC测试
	 */
	public static void FMCMACTest()
	{
		FMHash cmac = new FMHash();
		cmac.CMACTest();
	}
	
	/**
	 * 证书测试
	 * 流程为首先通过certkeyid号密钥生成P10,然后通过P10和cakeyid号私钥生成证书。
	 * 用cakeyid号公钥验证证书有效性
	 * 用certkeyid号私钥签名，生成的证书验证，是否通过
	 * 测试程序以SM2算法为例，RSA算法操作相同，将算法换成对应的字符串就可以
	 * @param path 证书生成路径
	 * @param certkeyid 证书对应的密钥对
	 * @param cakeyid 签发证书需要的密钥对
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public static void FMCerttest(String path, int certkeyid, int cakeyid,boolean isRSA,int keybits)
	{
		FMCert cert= new FMCert();
		cert.Certtest(path, certkeyid, cakeyid,isRSA,keybits);
	}
	
	/**
	 * keystore测试，进行keystore的存储、读取、删除操作
	 * keystore的创建是在操作开始的时候自动进行，如果原设备不存在keystore就创建一个，
	 * 若原设备已存在，则读取出来。
	 * @param path 证书路径
	 * @param certkeyid 证书密钥ID
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public static void FMKeyStoretest(String path, int certkeyid,boolean isRSA,int keybits)
	{
		FMKeyStore store = new FMKeyStore();
		store.KeyStoretest(path, certkeyid, isRSA, keybits);	
	}
	
	/**
	 * P12测试
	 * @param path 证书文件路径
	 * @param password keystore密码
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public static void FMPFXCertTest(String path, String password,boolean isRSA,int keybits)
	{
		FMP12 p12 = new FMP12();
		p12.PFXCertTest(path, password,isRSA,keybits);
	}
		
	/**
	 * P7数字信封封装拆封测试
	 * certpath为证书文件路径。操作之前，需要在keystore中存储证书和私钥。该证书为临时证书
	 * @param p7path 生成的P7信封文件路径
	 * @param certpath 证书文件路径
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public static void FMP7BEnvCertTest(String p7path,String certpath,boolean isRSA,int keybits,boolean isBase64)
	{
		FMP7 p7 = new FMP7();
		p7.P7BEnvCertTest(p7path, certpath, isRSA, keybits, isBase64);
	}
	
	/**
	 * P7数字签名验签测试
	 * certpath为证书文件路径。操作之前，需要在keystore中存储证书和私钥。该证书为临时证书
	 * @param p7path 生成的P7签名文件路径
	 * @param certpath 证书文件路径
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public static void FMP7BSignCertTest(String p7path,String certpath,boolean isRSA,int keybits,boolean isBase64){
		FMP7 p7 = new FMP7();
		p7.P7BSignCertTest(p7path, certpath, isRSA, keybits, isBase64);
	}
	
	public static void main(String[] args) throws InterruptedException
	{
		//准备步骤，生成后续操作用到的密钥
		PrepareKey(certkeyid, cakeyid, isRSA, keybits);
//		
		FMRSAEncAndDecTest();	    //RSA加解密测试
		FMRSASignAndVerifyTest();	//RSA签名验签测试
		FMSM2EncAndDecTest();	    //SM2加解密测试
		FMSM2SignAndVerifyTest();	//SM2签名验签测试
		FMSM2AgreementTest();		//SM2密钥协商测试
		FMSYSEncAndDecTest();		//对称密钥加解密测试
		FMSM1EncAndDecTest();	    //SM1加解密测试
//		
		FMSM3WithSM2Test();		    //SM3withSM2测试
		FMHashTest();               //哈希测试
		FMHMACTest();               //HMAC测试
		FMCMACTest();			    //CMAC测试
//		
//		//生成证书到指定路径,输入的两个密钥号设备必须已经存在密钥
		FMCerttest(certfile,certkeyid, cakeyid, isRSA,keybits);

		//keystore测试。证书为上步生成的证书路径，密钥号与证书密钥号相同
		FMKeyStoretest(certfile, certkeyid,isRSA,keybits);


		//P12测试
		FMPFXCertTest(p12file,"12345678",isRSA,keybits);

		//P7文件是否要求BASE64编码
		boolean isBase64 = false;
		//P7数字信封测试.此步需要在keystore中读取该证书相应的私钥，所以证书文件均使用keystore测试生成的文件
		FMP7BEnvCertTest(p7envfile,p7cert,isRSA,keybits,isBase64);

		//P7数字签名测试.此步需要在keystore中读取该证书相应的私钥，所以证书文件均使用keystore测试生成的文件
		FMP7BSignCertTest(p7signfile,p7cert,isRSA,keybits,isBase64);

		System.exit(0);
	}
}