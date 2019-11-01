import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;

import fisher.man.asn1.ASN1InputStream;
import fisher.man.asn1.DERObject;
import fisher.man.asn1.x509.X509CertificateStructure;
import fisher.man.jce.provider.X509CertificateObject;
import fisher.man.util.encoders.Base64;

/**
 *keystore的存储、删除、读取。
 */
public class FMKeyStore
{
	Logger logger = Logger.getLogger(FMKeyStore.class);
	/**
	 * keystore 测试
	* @param path 证书路径
	 * @param certkeyid 证书密钥ID
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public void KeyStoretest(String path, int certkeyid,boolean isRSA,int keybits){
		int rv = 0;
		if(isRSA){
			//从路径中读取证书（须和传入的密钥号是一对），并将证书和密钥存储到keystore中
			//算法和密钥长度需和证书中一致。
			rv = WriteKeyStore("12345678", "test", "12345678", certkeyid, keybits, "rsa", path);
			if(rv != 0)
			{
				logger.error("write cert to keystore error");
				return;
			}
			//读取keystore中证书
			X509Certificate cert = ExportCert("12345678", "test");
			if(cert == null)
			{
				logger.error("read cert from keystore error");
				return;
			}
			Key key = ExportKey("12345678", "test", "12345678");
			if(key == null)
			{
				logger.error("read key fromkeystore error");
				return;
			}
			
			//用keystore中密钥和证书进行签名验证
			//所以下面创建时需要根据证书和密钥的算法类型决定对应的类
			FMRsa rsa = new FMRsa();
			byte[] indata = new byte[1000];
			for(int i = 0;i<indata.length;i++)
			{
				indata[i] = (byte)i;
			}
			byte[] signdata = rsa.ExternalRSASign("SHA1", (PrivateKey)key, indata);
			if(signdata == null)
			{
				logger.error("keystore cert sign error");
				return;
			}
			boolean ret = rsa.ExternalRSAVerify("SHA1", cert.getPublicKey(), indata, signdata);
			if(ret){
				logger.info("keystore cert verify ok");
			}else{
				logger.error("keystore cert verify error");
			}	
		}else{
			//从路径中读取证书（须和传入的密钥号是一对），并将证书和密钥存储到keystore中
			//算法和密钥长度需和证书中一致。
			rv = WriteKeyStore("12345678", "test", "12345678", certkeyid, keybits, "sm2", path);
			if(rv != 0)
			{
				logger.error("write cert to keystore error");
				return;
			}
			
			//读取keystore中证书
			X509Certificate cert = ExportCert("12345678", "test");
			if(cert == null)
			{
				logger.error("read cert from keystore error");
				return;
			}
			Key key = ExportKey("12345678", "test", "12345678");
			if(key == null)
			{
				logger.error("read key from keystore error");
				return;
			}
			
			//用keystore中密钥和证书进行签名验证
			//所以下面创建时需要根据证书和密钥的算法类型决定对应的类
			FMSM2 sm2 = new FMSM2();
			byte[] indata = new byte[100];
			for(int i = 0;i<indata.length;i++)
			{
				indata[i] = (byte)i;
			}
			byte[] signdata = sm2.ExternalSM2Sign("SM3withSM2", (PrivateKey)key, indata);
			if(signdata == null)
			{
				logger.error("keystore cert sign error");
				return;
			}
			boolean ret = sm2.ExternalSM2Verify("SM3withSM2", cert.getPublicKey(), indata, signdata);
			if(ret)
			{
				logger.info("keystore cert verify ok");
			}
			else
			{
				logger.error("keystore cert verify error");
			}	
		}
	}
	
	/**
	 * 去头尾
	 * @param pem
	 * @return
	 * @throws IOException 
	 */
    public static final String BEGIN = "-----BEGIN";
    public static final String END = "-----END";
	public static String removeHeadAndTail(InputStream stream) throws IOException{
		BufferedReader reader = new BufferedReader(new InputStreamReader(stream));
		StringBuilder builder = new StringBuilder();
		String line = null;
		while((line = reader.readLine()) != null){
			if(line.indexOf(BEGIN) > -1 || line.indexOf(END) > -1 ){
				continue;
			}
			builder.append(line);
		}
		reader.close();
		return builder.toString().replaceAll("\r", "").replaceAll("\n", "");
	}
	
	/**
	 * 获取证书对象
	 * @param certPath 证书路径
	 * @return 证书路径
	 * @throws Exception
	 */
	public static X509Certificate transfer(String certPath) {
		try {
			InputStream ins = new FileInputStream(certPath);
			String content = removeHeadAndTail(ins);
			ins.close();
			X509CertificateStructure certStructure = X509CertificateStructure.getInstance(toDERObject(Base64.decode(content.getBytes())));
			X509Certificate cert =  new X509CertificateObject(certStructure);
			return cert;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * 将字节数组转换为DER格式的对象
	 * @param data
	 * @return
	 * @throws IOException
	 */
	private static DERObject toDERObject(byte[] data) throws IOException {
		ByteArrayInputStream inStream = new ByteArrayInputStream(data);
		ASN1InputStream dis = new ASN1InputStream(inStream);
		DERObject derObj = null;
		derObj = dis.readObject();
		return derObj;
	}	

	/**
	 * 向keystore中写入证书和对应的私钥。
	 * @param keystorepass keystore的密钥
	 * @param sAlias keystore中存储项的别名
	 * @param privatepass 私钥存储密钥
	 * @param keynum 私钥的密钥号
	 * @param bits 密钥长度
	 * @param alg 算法名称， 支持"RSA"或者"SM2"
	 * @param certpath 证书路径
	 * @return 结果 0为成功，其他为失败
	 */
	public int WriteKeyStore(String keystorepass, String sAlias, String privatepass,
            int keynum, int bits, String alg, String certpath) {
		X509Certificate x509cert = null;
		BufferedInputStream bis = null;
		FileInputStream fis = null;
		KeyStore keyStore = null;
		CertificateFactory cf = null;
		ByteArrayInputStream bi = null;
		try{
		//读取证书，组建证书对象
			try {
				fis = new FileInputStream(certpath);
				bis = new BufferedInputStream(fis);
				cf = CertificateFactory.getInstance("X.509","FishermanJCE");
				x509cert = (X509Certificate) cf.generateCertificate(bis);	
				fis.close();
				bis.close();		
			} catch (Exception e) {
				if(x509cert == null){                //base64证书带头尾
					x509cert = transfer(certpath);   //将base64编码修改为der编码
				}
			}
			if(x509cert == null){
				x509cert = transfer(certpath);       //base64证书不带头尾
				if(x509cert == null){                //证书为base64编码
					logger.error("get cert error");
					return -1;
				}
			}
		}catch(Exception ex){
			ex.printStackTrace();
			logger.error("get cert error");
			return -1;
		}
		
		//创建keystore对象
		try {
			keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
			keyStore.load(null, keystorepass.toCharArray());
		} catch (Exception ex) {
			logger.error("keystore load error");
			ex.printStackTrace();
			return -1;
		} 
		
		//读取私钥对象（假私钥）
		String Keynum = "";
		if(alg.equalsIgnoreCase("RSA")){
			Keynum = "RandomRSAPubKey" + keynum;
		}else if (alg.equalsIgnoreCase("SM2")){
			Keynum = "RandomSM2PubKey" + keynum;
		}
		
		KeyPairGenerator kpg = null;
		SecureRandom rand = null;
		PrivateKey prikey = null;
		try {
			kpg = KeyPairGenerator.getInstance(alg, "FishermanJCE");
			rand = SecureRandom.getInstance(Keynum, "FishermanJCE");
			kpg.initialize(bits, rand);
			KeyPair kp = kpg.generateKeyPair();
			prikey = kp.getPrivate();
		} catch (Exception e) {
			logger.error("export "+alg+" key error");
			e.printStackTrace();
			return -1;
		} 
		
		X509Certificate[] x509root = new X509Certificate[1];
		x509root[0] = x509cert; //
  
		//写入keystore中
		try {
			keyStore.setKeyEntry(sAlias, prikey, privatepass.toCharArray(), x509root);
			keyStore.store(null, keystorepass.toCharArray()); //store data to device
		} catch (Exception ex) {
			logger.error("KeyStore set entry error!");
			ex.printStackTrace();
			return -1;
		}
		return 0;
	}
	
	/**
	 * 仅存储证书到keystore中
	 * @param keystorepass keystore的密码
	 * @param sAlias keystore中存储项的别名
	 * @param certpath 证书路径
	 * @return 结果 0为成功，其他为失败
	 */
	public int WriteKeyStore(String keystorepass, String sAlias, String certpath)
	{
		X509Certificate x509cert = null;
		BufferedInputStream bis = null;
		FileInputStream fis = null;
		KeyStore keyStore = null;
		CertificateFactory cf = null;
		ByteArrayInputStream bi = null;

        try {
            fis = new FileInputStream(certpath);
            bis = new BufferedInputStream(fis);
            cf = CertificateFactory.getInstance("X.509","FishermanJCE");
                            x509cert = (X509Certificate) cf.generateCertificate(bis);
            fis.close();
            bis.close();
        } catch (Exception ex) {
            if(x509cert == null){                //base64编码带头尾的情况
				x509cert = transfer(certpath);   //将base64编码修改为der编码
			}
        }
        if(x509cert == null){                //base64不带头尾的情况
            x509cert = transfer(certpath);   //将base64编码修改为der编码
             if(x509cert == null){
            	 logger.error("X.509 CertificateFactoryinstance err!");
                return -1;
             }
        }
		
		//创建keystore对象
		try {
			keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
			keyStore.load(null, keystorepass.toCharArray());
			boolean rv = keyStore.containsAlias(sAlias);
			if(rv){
				keyStore.deleteEntry(sAlias);
				keyStore.setCertificateEntry(sAlias, x509cert);
			}else{
				keyStore.setCertificateEntry(sAlias, x509cert);
			}
			keyStore.store(null, keystorepass.toCharArray());
		} catch (Exception ex) 
		{
			logger.error("keystore set entry error");
			ex.printStackTrace();
			return -1;
		} 	    
		return 0;
	}
	
	/**
	 * 读取keystore中的证书
	 * @param keystorepass keystore的密码
	 * @param sAlias keystore中存储项的别名
	 * @return 证书
	 */
	public X509Certificate ExportCert(String keystorepass, String sAlias)
	{
		X509Certificate oCert = null;
		KeyStore keyStore = null;
		try 
		{
			keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
			keyStore.load(null, keystorepass.toCharArray());
			oCert = (X509Certificate)keyStore.getCertificate(sAlias);
		} catch (Exception ex) 
		{
			logger.error("keystore export cert error");
			ex.printStackTrace();
			return null;
		} 
		
		return oCert;
	}
	
	/**
	 * 读取keystore中的密钥
	 * @param keystorepass keystore的密码
	 * @param sAlias keystore中存储项的别名
	 * @param keypass 私钥存储密钥
	 * @return 密钥
	 */
	public Key ExportKey(String keystorepass, String sAlias, String keypass)
	{
		KeyStore keyStore = null;
		Key key = null;
		try {
			keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
			keyStore.load(null, keystorepass.toCharArray());
			key = keyStore.getKey(sAlias, keypass.toCharArray());
		} catch (Exception ex) {
			logger.error("keystore export key error");
			ex.printStackTrace();
			return null;
		} 
		return key;
	}
	
	/**
	 * 删除keystore中对应名称的存储项
	 * @param keystorepass keystore的密码
	 * @param sAlias keystore中存储项的别名
	 * @return 结果 0为成功，其他为失败
	 */
	public int DelentryFromKeystore(String keystorepass, String sAlias)
	{
		KeyStore keyStore = null;
		try {
			keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
			keyStore.load(null, keystorepass.toCharArray());
			keyStore.deleteEntry(sAlias);
			keyStore.store(null, keystorepass.toCharArray());
		} catch (Exception ex) {
			logger.error("keystore delete error");
			ex.printStackTrace();
			return -1;
		}
		return 0;
	}
}