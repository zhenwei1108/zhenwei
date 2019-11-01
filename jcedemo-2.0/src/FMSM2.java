import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECFieldFp;
import java.security.spec.EllipticCurve;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.apache.log4j.Logger;

import com.fmjce.crypto.dev.fmKeyAgreement;

import fisher.man.jce.provider.JCEECPrivateKey;
import fisher.man.jce.provider.JCEECPublicKey;
import fisher.man.jce.provider.asymmetric.ec.SM2KeyAgreement;

/**
 * SM2加密、解密、签名、验签的示例代码。
 * 构造函数中生成了一对临时密钥，
 * 这对密钥作用：在进行内部密钥运算时，需要传入密钥对象进行运算，否则报错。
 * 但实际调用密钥做运算是由SecureRandom参数指定内部密钥。临时密钥只做为对象参数传入。
 *
 */
public class FMSM2
{
	Logger logger = Logger.getLogger(FMSM2.class);
	
	KeyPair kp = null;//内部密钥时使用的临时密钥对象
	public FMSM2()
	{
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2","FishermanJCE");
			kpg.initialize(256);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("generate tmp SM2 keypair error");
			e.printStackTrace();
		}
	}
	
	/**
	 * SM2加解密测试
	 */
	public void SM2EncAndDecTest(){
		byte[] cipherdata =  null;
		byte[] tmpdata = null;
		/*********内部SM2加密***********/
		byte[] indata = new byte[32];
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
		
		cipherdata = InternalSM2Enc(2, indata);
		if(cipherdata == null){
			logger.error("internal sm2 enc error");
			return;
		}
		
//		ComFun.printfHexString(cipherdata);
		
		/*********内部sm2解密**************/
		tmpdata = InternalSM2Dec(2, cipherdata);
		if(tmpdata == null){
			logger.error("internal sm2 dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("sm2 internal Enc and Dec is ok");
		}else{
			logger.error("sm2 internal Enc and Dec is error");
		}
		
		/***********外部sm2密钥加密**************/
		KeyPair kp = GenerateExternalSM2KeyPair();
		cipherdata = ExternalSM2Enc(kp.getPublic(), indata);
		if(cipherdata == null){
			logger.error("external sm2 enc error");
			return;
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********外部sm2解密**************/
		tmpdata = ExternalSM2Dec(kp.getPrivate(), cipherdata);
		if(tmpdata == null){
			logger.error("external sm2 dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("sm2 external Enc and Dec is ok");
		}else{
			logger.error("sm2 external Enc and Dec is error");
		}
	}
	
	/**
	 * SM2签名验签测试
	 */
	public void SM2SignAndVerifyTest(){
		byte[] sign = null;
		boolean rv = false;
		/*********内部sm2签名(SM3withSM2)***********/
		byte[] indata = new byte[1000];//SM3withSM2方式输入数据不限长度
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
		
		sign = InternalSM2Sign("SM3withSM2", 2, indata);
		if(sign == null){
			logger.error("internal SM3withSM2 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********内部SM2验签(SM3withSM2)**************/
		rv = InternalSM2Verify("SM3withSM2", 2, indata, sign);
		if(rv){
			logger.info("internal SM3withSM2 verify ok");
		}else{
			logger.error("internal SM3withSM2 verify error");
			return;
		}
		
		/*********内部SM2签名(SM2)***********/
		byte[] indata32 = new byte[32];//SM2方式输入数据必须小于32字节
		sign = InternalSM2Sign("SM2", 2, indata32);
		if(sign == null){
			logger.error("internal sm2 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********内部SM2验签(SM2)**************/
		rv = InternalSM2Verify("SM2", 2, indata32, sign);
		if(rv){
			logger.info("internal SM2 verify ok");
		}else{
			logger.error("internal SM2 verify error");
			return;
		}
		
		/***********外部SM2密钥签名(SM3withSM2)**************/
		KeyPair kp = GenerateExternalSM2KeyPair();
		sign = ExternalSM2Sign("SM3withSM2", kp.getPrivate(), indata);
		if(sign == null){
			logger.error("external SM3withSM2 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********外部SM2验签**************/
		rv = ExternalSM2Verify("SM3withSM2", kp.getPublic(), indata, sign);
		if(rv){
			logger.info("external SM3withSM2 verify ok");
		}else{
			logger.error("external SM3withSM2 verify error");
			return;
		}
		
		/***********外部SM2密钥签名(SM2)**************/
		sign = ExternalSM2Sign("SM2", kp.getPrivate(), indata32);
		if(sign == null){
			logger.error("external SM2 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********外部SM2验签**************/
		rv = ExternalSM2Verify("SM2", kp.getPublic(), indata32, sign);
		if(rv){
			logger.info("external SM2 verify ok");
		}else{
			logger.error("external SM2 verify error");
			return;
		}
	}
	
	public void TestSM2Sign(){
	boolean rv = false;
	
	/***********外部SM2密钥签名(SM3withSM2)**************/
	byte p[] = 
	{
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF	
	};
	byte a[] = 
	{
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFC
	};
	byte b[] = 
	{
		(byte) 0x28, (byte) 0xE9, (byte) 0xFA, (byte) 0x9E, (byte) 0x9D, (byte) 0x9F, (byte) 0x5E, (byte) 0x34,
		(byte) 0x4D, (byte) 0x5A, (byte) 0x9E, (byte) 0x4B, (byte) 0xCF, (byte) 0x65, (byte) 0x09, (byte) 0xA7, 
		(byte) 0xF3, (byte) 0x97, (byte) 0x89, (byte) 0xF5, (byte) 0x15, (byte) 0xAB, (byte) 0x8F, (byte) 0x92, 
		(byte) 0xDD, (byte) 0xBC, (byte) 0xBD, (byte) 0x41, (byte) 0x4D, (byte) 0x94, (byte) 0x0E, (byte) 0x93
	};
	
	byte gx[] = 
	{
		(byte) 0x32, (byte) 0xC4, (byte) 0xAE, (byte) 0x2C, (byte) 0x1F, (byte) 0x19, (byte) 0x81, (byte) 0x19,
		(byte) 0x5F, (byte) 0x99, (byte) 0x04, (byte) 0x46, (byte) 0x6A, (byte) 0x39, (byte) 0xC9, (byte) 0x94, 
		(byte) 0x8F, (byte) 0xE3, (byte) 0x0B, (byte) 0xBF, (byte) 0xF2, (byte) 0x66, (byte) 0x0B, (byte) 0xE1, 
		(byte) 0x71, (byte) 0x5A, (byte) 0x45, (byte) 0x89, (byte) 0x33, (byte) 0x4C, (byte) 0x74, (byte) 0xC7
	};
	
	byte gy[] = 
	{
		(byte) 0xBC, (byte) 0x37, (byte) 0x36, (byte) 0xA2, (byte) 0xF4, (byte) 0xF6, (byte) 0x77, (byte) 0x9C, 
		(byte) 0x59, (byte) 0xBD, (byte) 0xCE, (byte) 0xE3, (byte) 0x6B, (byte) 0x69, (byte) 0x21, (byte) 0x53, 
		(byte) 0xD0, (byte) 0xA9, (byte) 0x87, (byte) 0x7C, (byte) 0xC6, (byte) 0x2A, (byte) 0x47, (byte) 0x40, 
		(byte) 0x02, (byte) 0xDF, (byte) 0x32, (byte) 0xE5, (byte) 0x21, (byte) 0x39, (byte) 0xF0, (byte) 0xA0
	};
	
	byte n[] =
	{
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFE, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, 
		(byte) 0x72, (byte) 0x03, (byte) 0xDF, (byte) 0x6B, (byte) 0x21, (byte) 0xC6, (byte) 0x05, (byte) 0x2B, 
		(byte) 0x53, (byte) 0xBB, (byte) 0xF4, (byte) 0x09, (byte) 0x39, (byte) 0xD5, (byte) 0x41, (byte) 0x23
	};
	
	byte[] pX = new byte[32];
	byte[] pY = new byte[32];
	byte[] pD = new byte[32];
      byte[] pPub = {
    		  (byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,
    		  (byte)0x0F,(byte)0xB0,(byte)0x5F,(byte)0x40,(byte)0xA5,(byte)0xFE,(byte)0x52,(byte)0xC9,(byte)0xEE,(byte)0x44,(byte)0x57,(byte)0x64, (byte)0x77,(byte)0x2A,(byte)0x93,(byte)0xA2,(byte)0xA8,(byte)0x86,(byte)0x57,(byte)0xAF,(byte)0x47,(byte)0x10,(byte)0xFE,(byte)0x17,(byte)0x9F,(byte)0xDA,(byte)0xAC,(byte)0xDE,(byte)0xF3,(byte)0x35,(byte)0x39,(byte)0x6B,
    		  (byte)0xCA,(byte)0x76,(byte)0xB5,(byte)0x7C,(byte)0xDE,(byte)0x31,(byte)0x0A,(byte)0x7B,(byte)0xAF,(byte)0xCA,(byte)0xD3,(byte)0xBD, (byte)0xC4,(byte)0xAF,(byte)0x32,(byte)0x68,(byte)0xDB,(byte)0x4F,(byte)0xA7,(byte)0xF9,(byte)0x46,(byte)0x1A,(byte)0x59,(byte)0x3B,(byte)0xB3,(byte)0x98,(byte)0x7A,(byte)0xD0,(byte)0x71,(byte)0xD9,(byte)0xD3,(byte)0x39
      };
	byte[] pPri = {
			(byte)0x00,(byte)0x01,(byte)0x00,(byte)0x00,
			(byte)0x0E,(byte)0xBE,(byte)0xB1,(byte)0x5C,(byte)0x14,(byte)0x5B,(byte)0x35,(byte)0x4C,(byte)0xD4,(byte)0xBF,(byte)0x53,(byte)0x77,(byte)0x18,(byte)0x32,(byte)0x8E,(byte)0x9B,(byte)0x09,(byte)0x32,(byte)0x2D,(byte)0xA2,(byte)0xCD,(byte)0x03,(byte)0xFF,(byte)0x1B,(byte)0x73,(byte)0x87,(byte)0xA0,(byte)0x25,(byte)0x46,(byte)0x93,(byte)0x3E,(byte)0xBD
	};
	
	BigInteger   BnD = null;
	java.security.spec.ECPoint pubPoin = null;
	
	System.arraycopy(pPub, 4, pX, 0, pX.length);
	System.arraycopy(pPub, 36, pY, 0, pY.length);
	
	BigInteger BnX = new BigInteger(1, pX);
	BigInteger BnY = new BigInteger(1, pY);
	pubPoin = new java.security.spec.ECPoint(BnX, BnY);
			
	System.arraycopy(pPri, 4, pD, 0, pD.length);
	BnD = new BigInteger(1, pD);	
	
	EllipticCurve EllC = new EllipticCurve(new ECFieldFp(new BigInteger(1,p)), new BigInteger(1, a), new BigInteger(1, b));	    		
	java.security.spec.ECPoint Gpoint = new java.security.spec.ECPoint(new BigInteger(1, gx), new BigInteger(1, gy));
	java.security.spec.ECParameterSpec spec =
	new java.security.spec.ECParameterSpec(EllC, Gpoint, new BigInteger(1, n), 1);
    
	java.security.spec.ECPublicKeySpec ecpubSpec = new java.security.spec.ECPublicKeySpec(pubPoin,spec);
	
	java.security.spec.ECPrivateKeySpec ecpriSpec = new java.security.spec.ECPrivateKeySpec(BnD, spec);
    
	KeyPair kp =  new KeyPair(new JCEECPublicKey("SM2", ecpubSpec), 
		 			   new JCEECPrivateKey("SM2", ecpriSpec));
	
	byte [] sign = {
		  (byte)0x30,(byte)0x44,(byte)0x02,(byte)0x1F,(byte)0x55,(byte)0xEA,(byte)0x41,(byte)0xB5,(byte)0x67,(byte)0x82,(byte)0x65,(byte)0x4E,(byte)0x75,(byte)0xC8,(byte)0xFA,(byte)0x8D,
		  (byte)0xA4,(byte)0xB0,(byte)0x2F,(byte)0x3E,(byte)0x97,(byte)0x4D,(byte)0x5E,(byte)0x27,(byte)0xB8,(byte)0xD1,(byte)0x72,(byte)0x28,(byte)0x8F,(byte)0x80,(byte)0xAE,(byte)0xA2,
		  (byte)0x52,(byte)0x74,(byte)0x47,(byte)0x02,(byte)0x21,(byte)0x00,(byte)0xCA,(byte)0x96,(byte)0x25,(byte)0x58,(byte)0xD7,(byte)0x59,(byte)0xC8,(byte)0x0D,(byte)0x0C,(byte)0x34,
		  (byte)0x70,(byte)0x9C,(byte)0x66,(byte)0x06,(byte)0x6A,(byte)0x43,(byte)0x43,(byte)0xA5,(byte)0x9F,(byte)0x12,(byte)0x10,(byte)0x9C,(byte)0x41,(byte)0x6F,(byte)0x1A,(byte)0x12,
		  (byte)0x0D,(byte)0x65,(byte)0x3F,(byte)0xE2,(byte)0xC3,(byte)0x74 
	};
	  
	byte[] indata32 = {
	  (byte)0xC5,(byte)0x03,(byte)0x7B,(byte)0x75,(byte)0xD9,(byte)0x98,(byte)0x68,(byte)0xE4,(byte)0xAA,(byte)0x54,(byte)0x8A,(byte)0x59,(byte)0x5A,(byte)0x05,(byte)0x19,(byte)0xA6,
	  (byte)0x88,(byte)0xD7,(byte)0xEB,(byte)0xCA,(byte)0x63,(byte)0xA6,(byte)0xE3,(byte)0xB3,(byte)0xC4,(byte)0xF5,(byte)0x89,(byte)0x70,(byte)0xA7,(byte)0xDB,(byte)0x61,(byte)0xC8
	};
	
	/*********外部SM2验签**************/
	rv = ExternalSM2Verify("SM2", kp.getPublic(), indata32, sign);
	if(rv){
		logger.info("TestSM2Sign ok");
	}else{
		logger.error("TestSM2Sign error");
		return;
	}
}
	
	/**
	 * 生成内部密钥对，将在指定密钥号中生成一对新密钥
	 * 若原设备该密钥号中不存在，则新生成一对，
	 * 若该密钥号中已存在，则重新生成后覆盖原密钥对
	 * @param keynum 密钥号
	 * @return 
	 */
	public KeyPair GenerateInternalSM2KeyPair(int keynum)
	{
		String keyid = "RandomSM2";
		keyid += keynum;
		KeyPair kp = null;
		
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2","FishermanJCE");
			kpg.initialize(256, ran);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("generate internal sm2 keypair error");
			e.printStackTrace();
			return null;
		}
		return kp;
	}
	
	/**
	 * 导出内部密钥对
	 * @param keynum 密钥号
	 * @return 密钥对
	 */
	public KeyPair ExportInternalSM2KeyPair(int keynum)
	{
		String keyid = "RandomSM2PubKey";
		keyid += keynum;
		KeyPair kp = null;
		
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2","FishermanJCE");
			kpg.initialize(256, ran);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("export internal sm2 keypair error");
			e.printStackTrace();
			return null;
		}
		return kp;
	}
	
	/**
	 * 生成外部密钥对
	 * @return 密钥对
	 */
	public KeyPair GenerateExternalSM2KeyPair()
	{
		KeyPair kp = null;
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2","FishermanJCE");
			kpg.initialize(256);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("generate external sm2 keypair error");
			e.printStackTrace();
			return null;
		}
		return kp;
	}
	
	/**
	 * *使用内部SM2密钥加密，内部密钥已经存在
	 * Cipher.getInstance(String, String)中第一个参数为指定算法类型
	 * "SM2/2/ZeroBytePadding":SM2公钥加密;
     * "SM2/1/ZeroBytePadding"：SM2私钥解密;
	 * @param keynum 密钥号
	 * @param indata 待加密数据
	 * @return 加密后的数据
	 */
	public byte[] InternalSM2Enc(int keynum, byte[] indata)
	{
		String keyid = "RandomSM2PubKey";
		keyid += keynum;
		byte[] ret;
		
		PublicKey pubkey = kp.getPublic();
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Cipher cipher = Cipher.getInstance("SM2/2/ZeroBytePadding", "FishermanJCE");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey, ran);//公钥参数不起实际作用，由ran来确定密钥号。
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("internal SM2 Enc error");
			e.printStackTrace();
			return null;
		}
		
		return ret;
	}
	
	/**
	 * 使用内部SM2密钥解密，内部密钥已经存在
	 * @param keynum 密钥号
	 * @param indata 待解密的数据
	 * @return 解密后的数据
	 */
	public byte[] InternalSM2Dec(int keynum, byte[] indata)
	{
		String keyid = "RandomSM2PubKey";
		keyid += keynum;
		byte[] ret;
		
		PrivateKey prikey = kp.getPrivate();
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Cipher cipher = Cipher.getInstance("SM2/1/ZeroBytePadding", "FishermanJCE");
			cipher.init(Cipher.DECRYPT_MODE, prikey, ran);//私钥参数不起实际作用，由ran来确定密钥号。
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("internal SM2 Dec error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 外部密钥加密
	 * @param pubkey SM2公钥
	 * @param indata 待加密的数据
	 * @return 加密后的数据
	 */
	public byte[] ExternalSM2Enc(PublicKey pubkey, byte[] indata)
	{
		byte[] ret = null;
		try{
			Cipher cipher = Cipher.getInstance("SM2/2/ZeroBytePadding", "FishermanJCE");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey);
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("external sm2 enc error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 外部密钥加密
	 * @param prikey SM2私钥
	 * @param indata 待解密的数据
	 * @return 解密后的数据
	 */
	public byte[] ExternalSM2Dec(PrivateKey prikey, byte[] indata)
	{
		byte[] ret = null;
		try{
			Cipher cipher = Cipher.getInstance("SM2/1/ZeroBytePadding", "FishermanJCE");
			cipher.init(Cipher.DECRYPT_MODE, prikey);
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("external sm2 dec error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 内部密钥签名，使用设备内部已经存在的密钥
	 * @param alg 摘要算法，支持算法：SM3withSM2或者SM2
	 * @param keynum 密钥号
	 * @param indata 待签名数据
	 * @return 签名后的数据
	 */
	public byte[] InternalSM2Sign(String alg, int keynum, byte[] indata)
	{
		byte[] ret = null; 
		String keyid = "RandomSM2PubKey";
		keyid = keyid + keynum;//索引号
		
		PrivateKey prikey = kp.getPrivate();
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Signature sg = Signature.getInstance(alg, "FishermanJCE");
			sg.initSign(prikey, ran);//私钥参数不起实际作用，由ran来确定密钥号。
			sg.update(indata);
			ret = sg.sign();
		}catch(Exception e){
			logger.error("internal sm2 sign error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 内部sm2密钥验签,需要将内部密钥导出组成对象后进行。
	 * @param alg 摘要算法
	 * @param keynum 密钥号
	 * @param indata 原始数据
	 * @param signdata 签名后的数据
	 * @return 验签结果 true或false
	 */
	public boolean InternalSM2Verify(String alg, int keynum, byte[] indata, byte[] signdata)
	{
		boolean rv = false; 
		String keyid = "RandomSM2PubKey";//该表示不生成内部RSA密钥对，可以使用该标识导出已存在的设备内部RSA公钥。
		keyid = keyid + keynum;
		
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("SM2", "FishermanJCE");		
			kpg.initialize(256, ran);			
			KeyPair kpin = kpg.generateKeyPair();//导出设备内部已存在的sm2公钥。
			
			Signature sg = Signature.getInstance(alg, "FishermanJCE");
			sg.initVerify(kpin.getPublic());
			sg.update(indata);
			if(sg.verify(signdata)){
				rv = true;
			}else{
				rv = false;
			}	
		}catch(Exception e){
			logger.error("internal sm2 verify error");
			e.printStackTrace();
			return false;
		}
		return rv;
	}
	
	/**
	 * 外部密钥签名，使用设备内部已经存在的密钥
	 * @param alg 摘要算法
	 * @param prikey SM2私钥
	 * @param indata 待签名的数据
	 * @return 签名后的数据
	 */
	public byte[] ExternalSM2Sign(String alg, PrivateKey prikey, byte[] indata)
	{
		byte[] ret = null; 
		
		try{
			Signature sg = Signature.getInstance(alg, "FishermanJCE");
			sg.initSign(prikey);
			sg.update(indata);
			ret = sg.sign();
		}catch(Exception e){
			logger.error("external sm2 sign error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 外部SM2验签
	 * @param alg 摘要算法
	 * @param pubkey SM2公钥
	 * @param indata 原始数据
	 * @param signdata 签名数据
	 * @return 验签结果 true或false
	 */
	public boolean ExternalSM2Verify(String alg, PublicKey pubkey, byte[] indata, byte[] signdata)
	{
		boolean rv = false; 
	
		try{
			Signature sg = Signature.getInstance(alg, "FishermanJCE");
			sg.initVerify(pubkey);
			sg.update(indata);
			if(sg.verify(signdata)){
				rv = true;
			}else{
				rv = false;
			}	
		}catch(Exception e){
			logger.error("external sm2 verify error");
			e.printStackTrace();
			return false;
		}
		return rv;
	}
	public void agreementtest(){
		int rv;
		int alg = 0;
		int hkey = 1;
		int u32keybits = 16;
		byte[] pu8SponsorID = new byte[16];
		for(int i = 0; i < 16; i ++)
		{
			pu8SponsorID[i] = 0;
		}
		int SponsorIDLen = pu8SponsorID.length;
		
		
		byte[] pu8ResponsorID = new byte[16];
		for(int i = 0; i < 16; i ++)
		{
			pu8ResponsorID[i] = 1;
		}
		int ResponsorIDLen = pu8ResponsorID.length;
		
		byte[] pSponsorPubKey = new byte[68];
		byte[] pSponsorTmpPub = new byte[68];
		int[] phAgreementHandle = new int[1];
		
		byte[] pResponsorPubKey = new byte[68];
		byte[] pResponsorTmpPub = new byte[68];
		byte[] phKeyHandle = new byte[16];
		
		fmKeyAgreement fm = new  fmKeyAgreement();
		
//第一步
		logger.info("Step 1:");
		rv = fm.FM_CPC_GenerateAgreementDataWithECC(alg, hkey, u32keybits, pu8SponsorID, SponsorIDLen, pSponsorPubKey, pSponsorTmpPub, phAgreementHandle);
		if(rv == 0)
		{
			ComFun.printfHexString(pSponsorPubKey);
			ComFun.printfHexString(pSponsorTmpPub);
			for(int i = 0; i<1;i++)
			{
				logger.info(phAgreementHandle[i]);
			}
		}
		
//第二步	
		logger.info("Step 2:");
		rv = fm.FM_CPC_GenerateAgreementDataAndKeyWithECC(alg, hkey, u32keybits, pu8ResponsorID, ResponsorIDLen, pu8SponsorID, SponsorIDLen, pSponsorPubKey, pSponsorTmpPub, pResponsorPubKey, pResponsorTmpPub, phKeyHandle);
		if(rv == 0)
		{
			ComFun.printfHexString(pResponsorPubKey);
			ComFun.printfHexString(pResponsorTmpPub);
			ComFun.printfHexString(phKeyHandle);
		}
		else {
			logger.info("error");
		}
		
//第三步
		logger.info("Step 3:");
		int phAgreementHandle_3 = phAgreementHandle[0];
		byte[] phKeyHandle_3 = new byte[32];
		
		
		rv = fm.FM_CPC_GenerateKeyWithECC(alg, pu8ResponsorID, ResponsorIDLen, pResponsorPubKey, pResponsorTmpPub, phAgreementHandle_3, phKeyHandle_3);
		if(rv == 0)
		{
			ComFun.printfHexString(phKeyHandle_3);
		}
	}
	
	public void agreementtestSM2_Soft(){
		KeyPair sponserKp = GenerateExternalSM2KeyPair();
		KeyPair sponserTmpKp = GenerateExternalSM2KeyPair();
		KeyPair responserKp = GenerateExternalSM2KeyPair();
		KeyPair responserTmpKp = GenerateExternalSM2KeyPair();

		PublicKey sponserPub = sponserKp.getPublic();
		PrivateKey sponserPri = sponserKp.getPrivate();
		PublicKey sponserTmpPub = sponserTmpKp.getPublic();
		PrivateKey sponserTmpPri = sponserTmpKp.getPrivate();

		PublicKey responserPub = responserKp.getPublic();
		PrivateKey responserPri = responserKp.getPrivate();
		PublicKey responserTmpPub = responserTmpKp.getPublic();
		PrivateKey responserTmpPri = responserTmpKp.getPrivate();
		
		SM2KeyAgreement mySM2KeyAgreement = new SM2KeyAgreement();
		
		mySM2KeyAgreement.SetKeyPairs(sponserPub, sponserPri, sponserTmpPub, sponserTmpPri, 
				responserPub, responserTmpPub);
		SecretKey sponsorSecretKey =  mySM2KeyAgreement.SponsorGenSM2(128, "AES");
		
		mySM2KeyAgreement.SetKeyPairs(responserPub, responserPri, responserTmpPub, responserTmpPri, 
				sponserPub, sponserTmpPub);
		SecretKey responsorSecretKey = mySM2KeyAgreement.ResponsorGenSM2(128, "AES");
		
		if(responsorSecretKey.equals(sponsorSecretKey))
		{
			logger.info("agreementtestSM2_Soft ok!");
		}
		else
		{
			logger.error("agreementtestSM2_Soft err!");
		}
		
		
	}

}