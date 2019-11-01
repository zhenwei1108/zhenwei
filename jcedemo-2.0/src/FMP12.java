import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.log4j.Logger;


public class FMP12 {
	Logger logger = Logger.getLogger(FMP12.class);
	/**
	 * P12测试
	 * @param path 证书文件路劲
	 * @param password keystore密码
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public void PFXCertTest(String path, String password,boolean isRSA,int keybits){
		KeyPair kp = null;
		byte [] buffer = null;
		try{
			KeyPairGenerator kpg = KeyPairGenerator.getInstance(isRSA?"RSA":"SM2","FishermanJCE");
			kpg.initialize(keybits);
			kp = kpg.generateKeyPair();
			
			PublicKey pubKey = kp.getPublic();
			PrivateKey privateKey = kp.getPrivate();
			Date notBefore = new Date();
			Date notAfter = new Date(notBefore.getTime() + 3650 * 24 * 60 * 60 * 1000L);
			X509Certificate caCert = FMCert.CreateX509Certificate(true, 
					true, 
					pubKey, 
					"C=CN1,ST=SD,L=WH,O=fisherman,OU=JMJ,CN=CA",
					notBefore,notAfter,
					null, 
					privateKey, 
					isRSA,
					false);
			X509Certificate usrCert = FMCert.CreateX509Certificate(false, 
					false, 
					caCert.getPublicKey(), 
					"C=CN2,ST=SD,L=WH,O=fisherman,OU=JMJ,CN=CA",
					notBefore,notAfter,
					caCert, 
					privateKey, 
					isRSA,
					false);
			
			buffer = CreatePfx(caCert,usrCert,kp.getPrivate(),password);
		}catch(Exception e){
			logger.error("gen pfx buffer error");
			e.printStackTrace();
			return;
		}		

		try{
	        BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(new File(path)));   
	        outputStream.write(buffer);   
	        outputStream.flush();   
	        outputStream.close(); 
		}catch(Exception e){
			e.printStackTrace();
			logger.error("write pfx cert to file error");
			return;
		}
		logger.info("write pfx cert to file OK");
	}
	
	/**
	 * 创建PFX证书
	 * @param rootCert 根证书，可信证书
	 * @param cert 证书
	 * @param certPrivateKey 证书私钥
	 * @param protectedPassword 密码
	 * @return P12格式的证书字节数组
	 * @throws Exception
	 */
	public static byte[] CreatePfx(X509Certificate rootCert,X509Certificate cert,PrivateKey certPrivateKey,String protectedPassword) throws Exception{
		KeyStore keyStore  = KeyStore.getInstance("PKCS12","FishermanJCE");
        
		keyStore.load(null,protectedPassword.toCharArray());
		keyStore.setKeyEntry("pfxCert", certPrivateKey, protectedPassword.toCharArray(),new X509Certificate[]{cert,rootCert});
		
		KeyStore.TrustedCertificateEntry trustEntry = new KeyStore.TrustedCertificateEntry(rootCert);
		keyStore.setEntry("heh", trustEntry, null);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		keyStore.store(baos,protectedPassword.toCharArray());
		byte[] buffer = baos.toByteArray();
		baos.close();
		return buffer;
	}
}
