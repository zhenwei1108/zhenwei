import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.log4j.Logger;

/**
 * SM1加解密
 */
public class FMSM1
{
	Logger logger = Logger.getLogger(FMSM1.class);
	public static final int DATALEN = 16*1024;
	SecretKey key = null;
	/**
	 * 生成用于内部密钥加解密的临时密钥对象
	 */
	public FMSM1()
	{
		try{
			KeyGenerator skg = KeyGenerator.getInstance("SM1", "FishermanJCE");
			skg.init(128);
			key = skg.generateKey();
		}catch(Exception e){
			logger.error("gen SM1 key fail");
			e.printStackTrace();
		}
	}
	
	/**
	 * SM1加解密测试
	 */
	public void SM1EncAndDecTest(){
		byte[] cipherdata = null;
		byte[] tmpdata = null;
		//CBC打补丁模式  加密
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

		/*********内部SM1加密**************/
		cipherdata = InternalSM1Enc(2, "CBC", true, indata, iv);
		if(cipherdata==null){
			logger.error("SM1 internal enc is error!");
			return;
		}else{
			logger.info("SM1 internal enc is ok!");
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********内部SM1解密**************/
		//CBC打补丁模式解密
		tmpdata = InternalSM1Dec(2, "CBC", true, cipherdata, iv);
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("SM1 internal Enc and Dec is ok");
		}else{
			logger.error("SM1 internal Enc and Dec is error");
			return;
		}
		
		/*********外部SM1加密**************/
		SecretKey sm1Key = ExportInternalKey(1);
		//SecretKey sm1Key = GenerateInternalKey(1);
		cipherdata = ExternalSM1Enc("CBC", true, indata, sm1Key, iv);
		if(cipherdata==null){
			logger.error("SM1 external enc is error!");
			return;
		}else{
			logger.info("SM1 external enc is ok!");
		}
//		ComFun.printfHexString(cipherdata);
		

		/*********外部SM1加密**************/
		//CBC打补丁模式解密
		tmpdata = ExternalSM1Dec("CBC", true, cipherdata, sm1Key, iv);
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("SM1 external Enc and Dec is ok");
		}else{
			logger.error("SM1 external Enc and Dec is error");
			return;
		}
		
		//该部分用于大数据处理	，数据超过DATALEN时用该方法处理	
		indata = new byte[DATALEN+1024];
		for(int i=0;i<indata.length;i++){
			indata[i] = (byte)i;
		}
		/*********外部SM1加密**************/
		cipherdata = ExternalSM1MultiEnc("CBC", true, indata, sm1Key, iv);
		if(cipherdata==null){
			logger.error("SM1 external multiple enc is error!");
			return;
		}else{
			logger.info("SM1 external multiple enc is ok!");
		}
//		ComFun.printfHexString(cipherdata);
		
		/*********外部SM1加密**************/
		//CBC打补丁模式解密
		tmpdata = ExternalSM1MultiDec("CBC", true, cipherdata, sm1Key, iv);
		if(new String(indata).equalsIgnoreCase(new String(tmpdata))){
			logger.info("SM1 external multiple Enc and Dec is ok");
		}else{
			logger.error("SM1 external multiple Enc and Dec is error");
			return;
		}
	}
	/**
	 * 导出SM1密钥
	 * @param keyid 密钥号	
	 * @return SM1密钥
	 */
	public SecretKey ExportInternalKey(int keyid){
		SecretKey sm1key = null;
		String keyalg = "RandomSM1InnerKey"+keyid;
		try {
			SecureRandom ran = SecureRandom.getInstance(keyalg, "FishermanJCE");
			KeyGenerator skg = KeyGenerator.getInstance("SM1", "FishermanJCE");
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
	 * @return SM1密钥
	 */
	public SecretKey GenerateInternalKey(int keyid){
		SecretKey sm1key = null;
		String keyalg = "RandomSM1"+keyid;
		try {
			SecureRandom ran = SecureRandom.getInstance(keyalg, "FishermanJCE");
			KeyGenerator skg = KeyGenerator.getInstance("SM1", "FishermanJCE");
			skg.init(128, ran);
			sm1key = skg.generateKey();
		} catch (Exception e) {
			logger.error("gen SM1 key fail,keynum is "+keyid);
			e.printStackTrace();
		}
		return sm1key;
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
	public byte[] InternalSM1Enc(int keyid, String mode, boolean ispad, byte[] indata, byte[] iv)
	{
		String alg = "SM1" + "/" + mode + "/";
		byte[] cipherdata = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}
		String sysalg = "RandomSM1" + keyid;
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
	public byte[] InternalSM1Dec(int keyid, String mode, boolean ispad, byte[] indata, byte[] iv)
	{
		String alg = "SM1" + "/" + mode + "/";
		byte[] data = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}

		String sysran = "RandomSM1" + keyid;
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
	
	/**
	 * 外部对称密钥加密运算
	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待加密数据
	 * @param keyBuf 外部密钥
	 * @param iv
	 * @return 加密后的数据
	 */
	public byte[] ExternalSM1Enc(String mode, boolean ispad,  byte[] indata, SecretKey keyBuf, byte[] iv)
	{
		String alg = "SM1" + "/" + mode + "/";
		byte[] cipherdata = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}

		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"SM1/ECB/NOPADDING"为SM1算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.ENCRYPT_MODE, keyBuf, ivspe);
			}else{
				cp.init(Cipher.ENCRYPT_MODE, keyBuf);
			}
			cipherdata = cp.update(indata);
			tail = cp.doFinal();
		}catch(Exception e){
			logger.error(alg+" external enc error");
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
	 * 外部对称密钥解密运算
 	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待解密数据
	 * @param keyBuf 外部密钥
	 * @param iv
	 * @return 解密后的数据
	 */
	public byte[] ExternalSM1Dec(String mode, boolean ispad, byte[] indata, SecretKey keyBuf, byte[] iv)
	{
		String alg = "SM1" + "/" + mode + "/";
		byte[] data = null;
		byte[] tail = null;
		IvParameterSpec ivspe = null;
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}
		
		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"SM1/ECB/NOPADDING"为SM1算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.DECRYPT_MODE, keyBuf, ivspe);
			}else{
				cp.init(Cipher.DECRYPT_MODE, keyBuf);
			}
			data = cp.update(indata);
			tail = cp.doFinal();
		}catch(Exception e){
			logger.error(alg+" external dec error");
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
	
	/**
	 * 外部分批对称密钥加密运算
	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待加密数据
	 * @param keyBuf 外部密钥
	 * @param iv
	 * @return 加密后的数据
	 */
	public byte[] ExternalSM1MultiEnc(String mode, boolean ispad,  byte[] indata, SecretKey keyBuf, byte[] iv)
	{
		String alg = "SM1" + "/" + mode + "/";
		int len = indata.length;//输入总数据长度
		byte[] cipherdata = new byte[len+16];//密文长度，考虑到可能需要打补丁，则密文需要预留空间
		byte[] tail = null;	//最后final得到的数据
		byte[] tempData = null;//分批处理得到的数据
		int tailLen = 0;//剩下需要处理的数据长度
		int offset = 0;//已经处理的输入数据的长度
		int cipheroffset = 0;//得到数据的长度
		IvParameterSpec ivspe = null;
		
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}

		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"SM1/ECB/NOPADDING"为SM1算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.ENCRYPT_MODE, keyBuf, ivspe);
			}else{
				cp.init(Cipher.ENCRYPT_MODE, keyBuf);
			}
			
			while(true)//有数据就一直处理
			{
				tailLen = len - offset;//剩下数据=数据总长度-已经处理的数据
				if (tailLen > DATALEN)//剩下数据>一次能够处理的长度
				{
					tempData = cp.update(indata, offset, DATALEN);//一次仅能处理DATALEN长度
					System.arraycopy(tempData, 0, cipherdata, cipheroffset, tempData.length);//保存得到的结果
					offset += DATALEN; //计算已处理的数据
					cipheroffset += tempData.length;//计算已得到的密文长度
				}
				else
				{//剩下的数据<=DATALEN
					tempData = cp.update(indata, offset, tailLen);//计算剩下的数据
					tail = cp.doFinal();//dofinal补丁或最后一块的数据加密结果
					//将处理的结果拷贝到密文缓冲中
					System.arraycopy(tempData, 0, cipherdata, cipheroffset, tempData.length);
					cipheroffset += tempData.length;
					System.arraycopy(tail, 0, cipherdata, cipheroffset, tail.length);
					cipheroffset += tail.length;
					break;//已处理完毕，退出while循环
				}
			}
		}catch(Exception e){
			System.out.println(alg+" external enc error");
			e.printStackTrace();
			return null;
		}
		
		byte[] ret = new byte[cipheroffset];
		System.arraycopy(cipherdata, 0, ret, 0, cipheroffset);
		return ret;
	}
	
	/**
	 * 外部分批对称密钥解密运算
 	 * @param mode "CBC"或者"ECB"
	 * @param ispad true为内部打补丁，即输入数据可为任意长度;false为上层打补丁，即输入数据必须为密钥模长的整数倍
	 * @param indata 待解密数据
	 * @param keyBuf 外部密钥
	 * @param iv
	 * @return 解密后的数据
	 */
	public byte[] ExternalSM1MultiDec(String mode, boolean ispad, byte[] indata, SecretKey keyBuf, byte[] iv)
	{
		String alg = "SM1" + "/" + mode + "/";
		int len = indata.length;//输入总数据长度
		byte[] cipherdata = new byte[len];//明文缓冲
		byte[] tail = null;	//最后final得到的数据
		byte[] tempData = null;//分批处理得到的数据
		int tailLen = 0;//剩下需要处理的数据长度
		int offset = 0;//已经处理的输入数据的长度
		int cipheroffset = 0;//得到数据的长度
		IvParameterSpec ivspe = null;
		if(ispad){
			alg += "PKCS5PADDING";
		}else{
			alg += "NOPADDING";
		}
		
		try{
			/*
			 * alg:参数格式"算法名称/模式/打补丁方式"；
			 * 如"SM1/ECB/NOPADDING"为SM1算法，ECB模式，不打补丁
			 * "SM1/CBC/PKCS5PADDING"为SM1算法，CBC模式，打补丁
			 */
			Cipher cp = Cipher.getInstance(alg, "FishermanJCE");
			if(mode.equalsIgnoreCase("CBC")){
				ivspe = new IvParameterSpec(iv, 0, 16);
				cp.init(Cipher.DECRYPT_MODE, keyBuf, ivspe);
			}else{
				cp.init(Cipher.DECRYPT_MODE, keyBuf);
			}
			
			while(true)//有数据就一直处理
			{
				tailLen = len - offset;//剩下数据=数据总长度-已经处理的数据
				if (tailLen > DATALEN)//剩下数据>一次能够处理的长度
				{
					tempData = cp.update(indata, offset, DATALEN);//一次仅能处理DATALEN长度
					System.arraycopy(tempData, 0, cipherdata, cipheroffset, tempData.length);//保存得到的结果
					offset += DATALEN; //计算已处理的数据
					cipheroffset += tempData.length;//计算已得到的密文长度
				}
				else
				{//剩下的数据<=DATALEN
					tempData = cp.update(indata, offset, tailLen);//计算剩下的数据
					tail = cp.doFinal();//dofinal补丁或最后一块的数据加密结果
					//将处理的结果拷贝到密文缓冲中
					System.arraycopy(tempData, 0, cipherdata, cipheroffset, tempData.length);
					cipheroffset += tempData.length;
					System.arraycopy(tail, 0, cipherdata, cipheroffset, tail.length);
					cipheroffset += tail.length;
					break;//已处理完毕，退出while循环
				}
			}
		}catch(Exception e){
			System.out.println(alg+" external dec error");
			e.printStackTrace();
			return null;
		}
		byte[] ret = new byte[cipheroffset];
		System.arraycopy(cipherdata, 0, ret, 0, cipheroffset);
		return ret;
	}
}