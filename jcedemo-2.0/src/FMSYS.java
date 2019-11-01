import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;

/**
 *对称密钥操作
 */
public class FMSYS
{
	Logger logger = Logger.getLogger(FMSYS.class);
	SecretKey key = null;
	
	/**
	 * 生成用于内部密钥加解密的临时密钥对象
	 */
	public FMSYS()
	{
		try{
			KeyGenerator skg = KeyGenerator.getInstance("SM4", "FishermanJCE");
			skg.init(128);
			key = skg.generateKey();
		}catch(Exception e){
			logger.error("gen SM4 key fail");
			e.printStackTrace();
		}
	}
	
	/**
	 * 生成对称密钥对象，根据密钥算法和密钥长度（位长）生成
	 * @param alg  算法 支持：DESEDE;AES;SM1;SM4;DES;
	 * @param bits 密钥长度
	 * @return 对称密钥
	 */
	public SecretKey GenerateKey(String alg, int bits)
	{
		SecretKey key = null;
		try{
			KeyGenerator skg = KeyGenerator.getInstance(alg, "FishermanJCE");
			skg.init(bits);
			key = skg.generateKey();
		}catch(Exception e){
			logger.error("gen "+alg+" key fail");
			e.printStackTrace();
			return null;
		}
		
		return key;
	}
	
	/**
	 * 对称密钥加解密测试
	 */
	public void SYSEncAndDecTest(){
		byte[] sm4key = {0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
				(byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 0x76, 0x54, 0x32, 0x10};
		byte[] plainData = {0x01, 0x23, 0x45, 0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
				(byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, 0x76, 0x54, 0x32, 0x10};
		SecretKey key1 = new SecretKeySpec(sm4key, "SM4");
		byte[] cipherdata1 = SYSEnc(key1, "ECB", false, plainData, null);
		if(cipherdata1==null){
			logger.error("SM4  enc is error!");
			return;
		}else{
			logger.info("SM4  enc is ok!");
		}
//		ComFun.printfHexString(cipherdata1);
		/*****************AES*******************/
		//CBC打补丁模式  加密
		SecretKey key = GenerateKey("AES", 128);//可选择算法"DES" "DESEDE" "AES" "SM1" "SM4"
		byte[] indata = new byte[126];
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
		byte[] iv = new byte[16];//通过生成随机数生成初始化向量iv
		SecureRandom ran = null;
		try{
			ran = SecureRandom.getInstance("TrueRandom", "FishermanJCE");
			ran.nextBytes(iv);
		}catch(Exception e){
			logger.error("gen iv random error");
			e.printStackTrace();
		}
		
		byte[] cipherdata = SYSEnc(key, "CBC", true, indata, iv);
		if(cipherdata1==null){
			logger.error("AES  enc is error!");
			return;
		}else{
			logger.info("AES  enc is ok!");
		}
//		ComFun.printfHexString(cipherdata);
		
		//CBC打补丁模式解密
		byte[] tmpdata = SYSDec(key, "CBC", true, cipherdata, iv);
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("AES Enc and Dec is ok");
		}else{
			logger.error("AES Enc and Dec is error");
			return;
		}

		/*****************SM4*******************/
		//ECB不打补丁模式  加密
		//key = GenerateKey("SM4", 128);
		key = GenerateInternalKey(1);
		//key = ExportInternalKey(1);
		indata = new byte[128];
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
				
		cipherdata = SYSEnc(key, "ECB", false, indata, null);
		if(cipherdata==null){
			logger.error("SM4  enc is error!");
			return;
		}else{
			logger.info("SM4  enc is ok!");
		}
//		ComFun.printfHexString(cipherdata);
		
		//ECB不打补丁模式解密
		tmpdata = SYSDec(key, "ECB", false, cipherdata, null);
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("SM4 Enc and Dec is ok");
		}else{
			logger.error("SM4 Enc and Dec is error");
			return;
		}
		
		/*********内部SM4加密**************/
		cipherdata = InternalSM4Enc(1, "CBC", true, indata, iv);
		if(cipherdata==null){
			logger.error("SM4 internal enc is error!");
			return;
		}else{
			logger.info("SM4 internal enc is ok!");
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********内部SM4解密**************/
		//CBC打补丁模式解密
		tmpdata = InternalSM4Dec(1, "CBC", true, cipherdata, iv);
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("SM4 internal Enc and Dec is ok");
		}else{
			logger.error("SM4 internal Enc and Dec is error");
			return;
		}
	}
	
	/**
	 * 导出SM1密钥
	 * @param keyid 密钥号	
	 * @return SM4密钥
	 */
	public SecretKey ExportInternalKey(int keyid){
		SecretKey sm1key = null;
		String keyalg = "RandomSM4InnerKey"+keyid;
		try {
			SecureRandom ran = SecureRandom.getInstance(keyalg, "FishermanJCE");
			KeyGenerator skg = KeyGenerator.getInstance("SM4", "FishermanJCE");
			skg.init(128, ran);
			sm1key = skg.generateKey();
		} catch (Exception e) {
			logger.error("export SM1 key fail,keynum is "+keyid);
			e.printStackTrace();
		}
		return sm1key;
	}
	
	/**
	 * 生成SM1密钥
	 * @param keyid 密钥号	
	 * @return SM4密钥
	 */
	public SecretKey GenerateInternalKey(int keyid){
		SecretKey sm1key = null;
		String keyalg = "RandomSM4"+keyid;
		try {
			SecureRandom ran = SecureRandom.getInstance(keyalg, "FishermanJCE");
			KeyGenerator skg = KeyGenerator.getInstance("SM4", "FishermanJCE");
			skg.init(128, ran);
			sm1key = skg.generateKey();
		} catch (Exception e) {
			logger.error("gen SM1 key fail,keynum is "+keyid);
			e.printStackTrace();
		}
		return sm1key;
	}
	
	/**
	 * 对称密钥加密运算
	 * @param key 对称密钥
	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待加密数据
	 * @param iv
	 * @return 加密后的数据
	 */
	public byte[] SYSEnc(SecretKey key, String mode, boolean ispad, byte[] indata, byte[] iv)
	{
		String alg = "";
		byte[] cipherdata = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		alg = key.getAlgorithm();
		alg += "/";
		alg += mode;
		alg += "/";
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}
		
		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"AES/ECB/NOPADDING"为AES算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.ENCRYPT_MODE, key, ivspe);
			}else{
				cp.init(Cipher.ENCRYPT_MODE, key);
			}
			
			cipherdata = cp.update(indata);
			tail = cp.doFinal();
		}catch(Exception e){
			logger.error(alg+" enc error");
			e.printStackTrace();
			return null;
		}
		
		byte[] ret = null;
		if(tail != null){
			ret = new byte[cipherdata.length+tail.length];
			System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
			System.arraycopy(tail, 0, ret, cipherdata.length, tail.length);
		}else{
			ret = new byte[cipherdata.length];
			System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
		}
		return ret;
	}
	
	/**
	 * 对称密钥解密算法
	 * @param key 对称密钥
	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待解密数据
	 * @param iv
	 * @return 解密后的数据
	 */
	public byte[] SYSDec(SecretKey key, String mode, boolean ispad, byte[] indata, byte[] iv)
	{
		String alg = "";
		byte[] data = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		alg = key.getAlgorithm();
		alg += "/";
		alg += mode;
		alg += "/";
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}

		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"AES/ECB/NOPADDING"为AES算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.DECRYPT_MODE, key, ivspe);
			}else{
				cp.init(Cipher.DECRYPT_MODE, key);
			}
			data = cp.update(indata);
			tail = cp.doFinal();
		}catch(Exception e){
			logger.error(alg+" dec error");
			e.printStackTrace();
			return null;
		}
		byte[] ret = null;
		if(tail != null){
			ret = new byte[data.length+tail.length];
			System.arraycopy(data, 0, ret, 0, data.length);
			System.arraycopy(tail, 0, ret, data.length, tail.length);
		}else{
			ret = new byte[data.length];
			System.arraycopy(data, 0, ret, 0, data.length);
		}
		return ret;
	}
	
	/**
	 * 内部对称密钥加密运算
	 * @param keyid 密钥号
	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待加密数据
	 * @param iv
	 * @return 加密后的数据
	 */
	public byte[] InternalSM4Enc(int keyid, String mode, boolean ispad, byte[] indata, byte[] iv)
	{
		String alg = "SM4" + "/" + mode + "/";
		byte[] cipherdata = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}
		String sysalg = "RandomSM4" + keyid;
		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"SM1/ECB/NOPADDING"为SM1算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			SecureRandom ran = SecureRandom.getInstance(sysalg, "FishermanJCE");
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.ENCRYPT_MODE, key, ivspe, ran);
			}else{
				cp.init(Cipher.ENCRYPT_MODE, key, ran);
			}
			cipherdata = cp.update(indata);
			tail = cp.doFinal();
		}catch(Exception e){
			logger.error(alg+" internal enc error");
			e.printStackTrace();
			return null;
		}
		
		byte[] ret = null;
		if(tail != null){
			if(cipherdata == null){
				ret = new byte[tail.length];
				System.arraycopy(tail, 0, ret, 0, tail.length);
			}
			else {
			    ret = new byte[cipherdata.length+tail.length];
				System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
				System.arraycopy(tail, 0, ret, cipherdata.length, tail.length);
			}
		}else{
			ret = new byte[cipherdata.length];
			System.arraycopy(cipherdata, 0, ret, 0, cipherdata.length);
		}
		return ret;
	}
	
	/**
	 * 内部对称密钥解密运算
	 * @param keyid 密钥号
 	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待解密数据
	 * @param iv
	 * @return 解密后的数据
	 */
	public byte[] InternalSM4Dec(int keyid, String mode, boolean ispad, byte[] indata, byte[] iv)
	{
		String alg = "SM4" + "/" + mode + "/";
		byte[] data = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}

		String sysran = "RandomSM4" + keyid;
		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"SM1/ECB/NOPADDING"为SM1算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			SecureRandom ran = SecureRandom.getInstance(sysran, "FishermanJCE");
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.DECRYPT_MODE, key, ivspe, ran);
			}else{
				cp.init(Cipher.DECRYPT_MODE, key, ran);
			}
			data = cp.update(indata);
			tail = cp.doFinal();
		}catch(Exception e){
			logger.error(alg+" internal dec error");
			e.printStackTrace();
			return null;
		}
		byte[] ret = null;
		if(tail != null){
			if(data != null){
			ret = new byte[data.length+tail.length];
			System.arraycopy(data, 0, ret, 0, data.length);
			System.arraycopy(tail, 0, ret, data.length, tail.length);
			}else{
				ret = new byte[tail.length];
				System.arraycopy(tail, 0, ret, 0, tail.length);
			}
		}else{
			ret = new byte[data.length];
			System.arraycopy(data, 0, ret, 0, data.length);
		}
		return ret;
	}
}