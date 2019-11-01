import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import javax.crypto.Cipher;

import org.apache.log4j.Logger;

/**
 * rsa加密、解密、签名、验签的示例代码。
 * 构造函数中生成了两对临时密钥，一对1024密钥对，一对2048密钥对
 * 这两对密钥作用：在进行内部密钥运算时，需要传入密钥对象进行运算，否则报错。
 * 但实际调用密钥做运算是由SecureRandom参数指定内部密钥。两对临时密钥只做为对象参数传入。
 */
public class FMRsa
{
	Logger logger = Logger.getLogger(FMRsa.class);
	
	KeyPair kp1024 = null;//内部密钥时使用的临时密钥对象
	KeyPair kp2048 = null;
	public FMRsa()
	{
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA","FishermanJCE");
			kpg.initialize(1024);
			kp1024 = kpg.generateKeyPair();
		
			kpg.initialize(2048);
			kp2048 = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("generate tmp rsa keypair error");
			e.printStackTrace();
		}
	}
	/**
	 * RSA加解密测试
	 */
	public void RSAEncAndDecTest(){
		byte[] cipherdata = null;
		byte[] tmpdata = null;
		KeyPair kp = null;
		/*********内部RSA1024加密***********/
		byte[] indata = new byte[32];
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
		
		cipherdata = InternalKeyAndBitsRSAEnc(1, 1024, indata);
		if(cipherdata == null){
			logger.error("internal Rsa 1024 (RandomRSA-keynum-keybits) enc error");
			return;
		}
//		ComFun.printfHexString(cipherdata);
		/*********内部RSA1024解密**************/
		tmpdata = InternalKeyAndBitsRSADec(1, 1024, cipherdata);
		if(tmpdata == null){
			logger.error("internal Rsa 1024 (RandomRSA-keynum-keybits) dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("RSA 1024 internal Enc and Dec (RandomRSA-keynum-keybits) is ok");
		}else{
			logger.error("RSA 1024 internal Enc and Dec (RandomRSA-keynum-keybits) is error");
		}
		
		cipherdata = InternalRSAEnc(1, 1024, indata);
		if(cipherdata == null){
			logger.error("internal Rsa 1024 enc error");
			return;
		}
//		ComFun.printfHexString(cipherdata);
		/*********内部RSA1024解密**************/
		tmpdata = InternalRSADec(1, 1024, cipherdata);
		if(tmpdata == null){
			logger.error("internal Rsa 1024 dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("RSA 1024 internal Enc and Dec is ok");
		}else{
			logger.error("RSA 1024 internal Enc and Dec is error");
		}
		/*********内部RSA2048加密***********/
		cipherdata = InternalRSAEnc(2, 2048, indata);
		if(cipherdata == null){
			logger.error("internal Rsa 2048 enc error");
			return;
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********内部RSA2048解密**************/
		tmpdata = InternalRSADec(2, 2048, cipherdata);
		if(tmpdata == null){
			logger.error("internal Rsa 2048 dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("RSA 2048 internal Enc and Dec is ok");
		}else{
			logger.error("RSA 2048 internal Enc and Dec is error");
		}
		
		/***********外部RSA1024密钥加密**************/
		kp = GenerateExternalRSAKeyPair(1024);
		cipherdata = ExternalRSAEnc(kp.getPublic(), indata);
		if(cipherdata == null){
			logger.error("external Rsa 1024 enc error");
			return;
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********外部RSA1024解密**************/
		tmpdata =ExternalRSADec(kp.getPrivate(), cipherdata);
		if(tmpdata == null){
			logger.error("external Rsa 1024 dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("RSA 1024 external Enc and Dec is ok");
		}else{
			logger.error("RSA 1024 external Enc and Dec is error");
		}
		
		/***********外部RSA2048密钥加密**************/
		kp = GenerateExternalRSAKeyPair(2048);
		cipherdata = ExternalRSAEnc(kp.getPublic(), indata);
		if(cipherdata == null){
			logger.error("external Rsa 2048 enc error");
			return;
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********外部RSA2048解密**************/
		tmpdata = ExternalRSADec(kp.getPrivate(), cipherdata);
		if(tmpdata == null){
			logger.error("external Rsa 2048 dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("RSA 2048 external Enc and Dec is ok");
		}else{
			logger.error("RSA 2048 external Enc and Dec is error");
		}
		
		/*********软算法加密**************/
		kp = SoftRSAKeyPair(1024);
		cipherdata = SoftRSAEnc(kp.getPublic(), indata);
		if(cipherdata == null){
			logger.error("soft Rsa 1024 enc error");
			return;
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********软算法解密**************/
		tmpdata = SoftRSADec(kp.getPrivate(), cipherdata);
		if(tmpdata == null){
			logger.error("soft Rsa 1024 dec error");
			return;
		}
		//比较明文和解密出来数据是否一致
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("RSA 1024 soft Enc and Dec is ok");
		}else{
			logger.error("RSA 1024 soft Enc and Dec is error");
		}
	}
	
	/**
	 * RSA签名验签测试
	 */
	public void RSASignAndVerifyTest(){
		byte[] sign = null;
		boolean rv = false;
		KeyPair kp = null;
		/*********内部RSA1024签名***********/
		byte[] indata = new byte[100];
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
		sign = InternalRSASign("SHA1", 1, 1024, indata);
		if(sign == null){
			logger.error("internal Rsa 1024 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********内部RSA1024验签**************/
		rv = InternalRSAVerify("SHA1", 1, 1024, indata, sign);
		if(rv){
			logger.info("internal rsa 1024 verify ok");
		}else{
			logger.error("internal rsa 1024 verify error");
			return;
		}
		
		/*********内部RSA2048签名***********/
		sign = InternalRSASign("MD5", 2, 2048, indata);
		if(sign == null){
			logger.error("internal Rsa 2048 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********内部RSA2048验签**************/
		rv = InternalRSAVerify("MD5", 2, 2048, indata, sign);
		if(rv){
			logger.info("internal Rsa 2048 verify ok");
		}else{
			logger.error("internal Rsa 2048 verify error");
			return;
		}
		
		/***********外部RSA1024密钥签名**************/
		kp = GenerateExternalRSAKeyPair(1024);
		sign = ExternalRSASign("SHA224", kp.getPrivate(), indata);
		if(sign == null){
			logger.error("external Rsa 1024 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********外部RSA1024验签**************/
		rv = ExternalRSAVerify("SHA224", kp.getPublic(), indata, sign);
		if(rv){
			logger.info("external Rsa 1024 verify ok");
		}else{
			logger.error("external Rsa 1024 verify error");
			return;
		}
		
		/***********外部RSA2048密钥签名**************/
		kp = GenerateExternalRSAKeyPair(2048);
		sign = ExternalRSASign("SHA384", kp.getPrivate(), indata);
		if(sign == null){
			logger.error("external Rsa 2048 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********外部RSA2048验签**************/
		rv = ExternalRSAVerify("SHA384", kp.getPublic(), indata, sign);
		if(rv){
			logger.info("external Rsa 2048 verify ok");
		}else{
			logger.error("external Rsa 2048 verify error");
			return;
		}
		
		/*********软算法签名**************/
		kp = SoftRSAKeyPair(1024);
		sign = SoftRSASign(kp.getPrivate(), indata);
		if(sign == null){
			logger.error("external Rsa 2048 sign error");
			return;
		}
//		ComFun.printfHexString(sign);
		
		/*********软算法验签**************/
		rv = SoftRSAVerify(kp.getPublic(), indata, sign);
		if(rv){
			logger.info("soft Rsa 1024 verify ok");
		}else{
			logger.error("soft Rsa 1024 verify error");
			return;
		}
	}
	
	/**
	 * 生成内部密钥对，将在指定密钥号中生成一对新密钥
	 * 若原设备该密钥号中不存在，则新生成一对，
	 * 若该密钥号中已存在，则重新生成后覆盖原密钥对
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @return 密钥对
	 */
	public KeyPair GenerateInternalRSAKeyPair(int keynum, int keybits)
	{
		if(keybits != 1024&&keybits != 2048){
			logger.error("keybits "+keybits+" is not support");
			return null;
		}
		String keyid = "RandomRSA";
		keyid += keynum;
		KeyPair kp = null;
		
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA","FishermanJCE");
			kpg.initialize(keybits, ran);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("generate internal rsa keypair error");
//			e.printStackTrace();
			return null;
		}
		return kp;
	}
	
	/**
	 * 导出内部密钥对
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @return 密钥对
	 */
	public KeyPair ExportInternalRSAKeyPair(int keynum, int keybits)
	{
		if(keybits != 1024&&keybits != 2048){
			logger.error("keybits"+keybits+"is not support");
			return null;
		}
		String keyid = "RandomRSAPubKey";
		keyid += keynum;
		KeyPair kp = null;
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA","FishermanJCE");
			kpg.initialize(keybits, ran);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("export internal rsa keypair error");
			e.printStackTrace();
			return null;
		}
		return kp;
	}
	
	/**
	 * 导出外部密钥对
	 * @param keybits 密钥长度 1024或2048
	 * @return 密钥对
	 */
	public KeyPair GenerateExternalRSAKeyPair(int keybits)
	{
		KeyPair kp = null;
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA","FishermanJCE");//
			kpg.initialize(keybits);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("generate external  rsa keypair error");
			e.printStackTrace();
			return null;
		}
		return kp;
	}
	
	/**
	 * 软件实现生成密钥对
	 * @param keybits 密钥长度 1024或2048
	 * @return 密钥对
	 */
	public KeyPair SoftRSAKeyPair(int keybits)
	{
		KeyPair kp = null;
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSAS","FishermanJCE");//
			kpg.initialize(keybits);
			kp = kpg.generateKeyPair();
		}catch(Exception e){
			logger.error("generate external  rsa keypair error");
			e.printStackTrace();
			return null;
		}
		return kp;
	}

	/**
	 * 使用内部RSA密钥加密，内部密钥已经存在
	 * Cipher.getInstance(String, String)中第一个参数为指定算法类型
	 * "RSA"或"RSA/ECB/PKCS1PADDING":指定为RSA打补丁算法。及输入数据可以输入长度小于117字节的任意数据；
	 * "RSA/ECB/NoPadding":指定为RSA不打补丁算法，输入数据长度必须为keybits/8，由外部打补丁后传入；
     * "RSA/2/NoPadding":指定为RSA不打补丁的公钥加密;
     * "RSA/2/PKCS1PADDING":指定为RSA打补丁公钥加密;
     * "RSA/1/NOPADDING":指定为RSA不打补丁解密;
     * "RSA/1/PKCS1PADDING":指定为RSA打补丁解密;
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @param indata 要加密的数据
	 * @return 加密后的数据
	 */
	public byte[] InternalRSAEnc(int keynum, int keybits, byte[] indata)
	{
		String keyid = "RandomRSAPubKey";
		keyid += keynum;//keyId拼接索引号？
		byte[] ret;
		
		PublicKey pubkey = null;
		if(keybits == 1024){
			pubkey = kp1024.getPublic();
		}else if(keybits == 2048){
			pubkey = kp2048.getPublic();
		}else{
			logger.error("keybits "+keybits+" is not support");
			return null;
		}
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Cipher cipher = Cipher.getInstance("RSA", "FishermanJCE");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey, ran);//公钥参数不起实际作用，由ran来确定密钥号。
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("internal RSA Enc error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 使用内部RSA密钥解密，内部密钥已经存在
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @param indata 要解密的数据
	 * @return 解密后的数据
	 */
	public byte[] InternalRSADec(int keynum, int keybits, byte[] indata)
	{
		String keyid = "RandomRSAPubKey";
		keyid += keynum;
		byte[] ret;
		
		PrivateKey prikey = null;
		if(keybits == 1024){
			prikey = kp1024.getPrivate();
		}else if(keybits == 2048){
			prikey = kp2048.getPrivate();
		}else{
			logger.error("keybits "+keybits+" is not support");
			return null;
		}
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Cipher cipher = Cipher.getInstance("RSA", "FishermanJCE");
			cipher.init(Cipher.DECRYPT_MODE, prikey, ran);//私钥参数不起实际作用，由ran来确定密钥号。
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("internal RSA Enc error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 使用内部RSA密钥加密，内部密钥已经存在
	 * Cipher.getInstance(String, String)中第一个参数为指定算法类型
	 * "RSA"或"RSA/ECB/PKCS1PADDING":指定为RSA打补丁算法。及输入数据可以输入长度小于117字节的任意数据；
	 * "RSA/ECB/NoPadding":指定为RSA不打补丁算法，输入数据长度必须为keybits/8，由外部打补丁后传入；
     * "RSA/2/NoPadding":指定为RSA不打补丁的公钥加密;
     * "RSA/2/PKCS1PADDING":指定为RSA打补丁公钥加密;
     * "RSA/1/NOPADDING":指定为RSA不打补丁解密;
     * "RSA/1/PKCS1PADDING":指定为RSA打补丁解密;
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @param indata 要加密的数据
	 * @return 加密后的数据
	 */
	public byte[] InternalKeyAndBitsRSAEnc(int keynum, int keybits, byte[] indata)
	{
		String keyid = "RandomRSA" + "-" + keynum + "-" + keybits;
		byte[] ret;
		
		PublicKey pubkey = null;
		
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Cipher cipher = Cipher.getInstance("RSA", "FishermanJCE");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey, ran);//公钥参数不起实际作用，由ran来确定密钥号。
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("internal RSA Enc error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 使用内部RSA密钥解密，内部密钥已经存在
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @param indata 要解密的数据
	 * @return 解密后的数据
	 */
	public byte[] InternalKeyAndBitsRSADec(int keynum, int keybits, byte[] indata)
	{
		String keyid = "RandomRSA" + "-" + keynum + "-" + keybits;
		byte[] ret;
		
		PrivateKey prikey = null;

		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Cipher cipher = Cipher.getInstance("RSA", "FishermanJCE");
			cipher.init(Cipher.DECRYPT_MODE, prikey, ran);//私钥参数不起实际作用，由ran来确定密钥号。
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("internal RSA Enc error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 外部密钥加密
	 * @param pubkey RSA公钥
	 * @param indata 要加密的数据
	 * @return 加密后的数据
	 */
	public byte[] ExternalRSAEnc(PublicKey pubkey, byte[] indata)
	{
		byte[] ret = null;
		try{
			Cipher cipher = Cipher.getInstance("RSA", "FishermanJCE");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey);
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("external rsa enc error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 外部密钥解密
	 * @param prikey RSA私钥
	 * @param indata 要解密的数据
	 * @return 解密后的数据
	 */
	public byte[] ExternalRSADec(PrivateKey prikey, byte[] indata)
	{
		byte[] ret = null;
		try{
			Cipher cipher = Cipher.getInstance("RSA", "FishermanJCE");
			cipher.init(Cipher.DECRYPT_MODE, prikey);
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("external rsa dec error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 软算法加密
	 * @param pubkey RSA公钥
	 * @param indata 要加密的数据
	 * @return 加密后的数据
	 */
	public byte[] SoftRSAEnc(PublicKey pubkey, byte[] indata)
	{
		byte[] ret = null;
		try{
			Cipher cipher = Cipher.getInstance("RSA/SOFT/PKCS1PADDING", "FishermanJCE");
			cipher.init(Cipher.ENCRYPT_MODE, pubkey);
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("soft rsa enc error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 软算法解密
	 * @param prikey RSA私钥
	 * @param indata 要解密的数据
	 * @return 解密后的数据
	 */
	public byte[] SoftRSADec(PrivateKey prikey, byte[] indata)
	{
		byte[] ret = null;
		try{
			Cipher cipher = Cipher.getInstance("RSA/SOFT/PKCS1PADDING", "FishermanJCE");
			cipher.init(Cipher.DECRYPT_MODE, prikey);
			ret = cipher.doFinal(indata);
		}catch(Exception e){
			logger.error("soft rsa dec error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 内部密钥签名，使用设备内部已经存在的密钥
	 * @param hashalg 摘要算法，支持算法：SHA1, SHA224, SHA384, SHA512, MD2, MD5, MD4 
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @param indata 待签名数据
	 * @return 签名后的数据
	 */
	public byte[] InternalRSASign(String hashalg, int keynum, int keybits, byte[] indata)
	{
		String alg = hashalg + "withRSA";
		byte[] ret = null; 
		String keyid = "RandomRSAPubKey" + keynum;
		
		PrivateKey prikey = null;
		
		if(keybits == 1024){
			prikey = kp1024.getPrivate();
		}else if(keybits == 2048){
			prikey = kp2048.getPrivate();
		}else{
			logger.error("keybits "+keybits+" is not support");
			return null;
		}
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			Signature sg = Signature.getInstance(alg, "FishermanJCE");
			sg.initSign(prikey, ran);//私钥参数不起实际作用，由ran来确定密钥号。
			sg.update(indata);
			ret = sg.sign();
		}catch(Exception e){
			logger.error("internal rsa sign error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 内部rsa密钥验签,需要将内部密钥导出组成对象后进行。
	 * @param hashalg 摘要算法
	 * @param keynum 密钥号
	 * @param keybits 密钥长度 1024或2048
	 * @param indata 原始数据
	 * @param signdata 已签名数据
	 * @return 验签结果 true或false
	 */
	public boolean InternalRSAVerify(String hashalg, int keynum, int keybits, byte[] indata, byte[] signdata)
	{
		boolean rv = false; 
		String keyid = "RandomRSAPubKey" + keynum;//该表示不生成内部RSA密钥对，可以使用该标识导出已存在的设备内部RSA公钥。
		String alg = hashalg + "withRSA";
		
		try{
			SecureRandom ran = SecureRandom.getInstance(keyid, "FishermanJCE");
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "FishermanJCE");
			
			//初始化，指定密钥的模长，支持1024、2048；通过传递随机数对象指定密钥号。
			kpg.initialize(keybits, ran);
			KeyPair kp = null;
			kp = kpg.generateKeyPair();//导出设备内部已存在的RSA公钥。

			Signature sg = Signature.getInstance(alg, "FishermanJCE");
			sg.initVerify(kp.getPublic());
			sg.update(indata);
			if(sg.verify(signdata)){
				rv = true;
			}else{
				rv = false;
			}	
		}catch(Exception e){
			logger.error("internal rsa verify error");
			e.printStackTrace();
			return false;
		}
		return rv;
	}
	
	/**
	 * 外部密钥签名，使用设备内部已经存在的密钥
	 * @param hashalg 摘要算法，支持算法：SHA1, SHA224, SHA384, SHA512, MD2, MD5, MD4 
	 * @param prikey RSA私钥
	 * @param indata 待签名数据
	 * @return 签名后的数据
	 */
	public byte[] ExternalRSASign(String hashalg, PrivateKey prikey, byte[] indata)
	{
		String alg = hashalg + "withRSA";
		byte[] ret = null; 
		
		try{
			Signature sg = Signature.getInstance(alg, "FishermanJCE");
			sg.initSign(prikey);
			sg.update(indata);
			ret = sg.sign();
		}catch(Exception e){
			logger.error("external rsa sign error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 外部RSA密钥验签
	 * @param hashalg 摘要算法
	 * @param pubkey RSA公钥
	 * @param indata 原始数据
	 * @param signdata 签名数据
	 * @return 验签结果 true或false
	 */
	public boolean ExternalRSAVerify(String hashalg, PublicKey pubkey, byte[] indata, byte[] signdata)
	{
		boolean rv = false; 
		String alg = hashalg + "withRSA";
	
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
			logger.error("external rsa verify error");
			e.printStackTrace();
			return false;
		}
		return rv;
	}
	
	/**
	 * 软算法签名
	 * @param hashalg 摘要算法，支持算法：SHA1, SHA224, SHA384, SHA512, MD2, MD5, MD4 
	 * @param prikey RSA私钥
	 * @param indata 待签名数据
	 * @return 签名后的数据
	 */
	public byte[] SoftRSASign(PrivateKey prikey, byte[] indata)
	{
		byte[] ret = null; 
		
		try{
			Signature sg = Signature.getInstance("RSASOFT", "FishermanJCE");
			sg.initSign(prikey);
			sg.update(indata);
			ret = sg.sign();
		}catch(Exception e){
			logger.error("soft rsa sign error");
			e.printStackTrace();
			return null;
		}
		return ret;
	}
	
	/**
	 * 软算法验签
	 * @param hashalg 摘要算法
	 * @param pubkey RSA公钥
	 * @param indata 原始数据
	 * @param signdata 签名数据
	 * @return 验签结果 true或false
	 */
	public boolean SoftRSAVerify(PublicKey pubkey, byte[] indata, byte[] signdata)
	{
		boolean rv = false; 
	
		try{
			Signature sg = Signature.getInstance("RSASOFT", "FishermanJCE");
			sg.initVerify(pubkey);
			sg.update(indata);
			if(sg.verify(signdata)){
				rv = true;
			}else{
				rv = false;
			}	
		}catch(Exception e){
			logger.error("soft rsa verify error");
			e.printStackTrace();
			return false;
		}
		return rv;
	}
}