import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.apache.log4j.Logger;

import fisher.man.asn1.x509.X509Extensions;
import fisher.man.asn1.x509.X509Name;
import fisher.man.jce.PKCS10CertificationRequest;
import fisher.man.util.encoders.Base64;
import fisher.man.x509.X509V3CertificateGenerator;


/**
 * P10操作
 */
public class FMP10 {
	Logger logger = Logger.getLogger(FMP10.class);
	/**
	 * 生成P10请求，为BASE64编码
	 * @param keyalg 密钥算法，支持"RSA"或者"SM2"
	 * @param signalg 签名算法，支持"SHA1withRSA","SM3withSM2","MD5withRSA","SHA256withRSA"等
	 * @param keynum 密钥号
	 * @param keybits 密钥长度
	 * @param dn p10主题，中间用","隔开，例如"C=CN,ST=SD,L=WH,O=fisherman,OU=JMJ,CN=Requested Test Certificate"
	 * @return  
	 */
	public byte[] CreateP10Request(String keyalg, String signalg, int keynum, int keybits, String dn)
	{
		KeyPair kp = null;
		try{
			KeyPairGenerator kpgen = KeyPairGenerator.getInstance(keyalg, "FishermanJCE");
			String keyid = "Random" + keyalg + "PubKey" + keynum;
			SecureRandom rand = SecureRandom.getInstance(keyid, "FishermanJCE");//用内部1号密钥
			kpgen.initialize(keybits, rand);
			kp = kpgen.generateKeyPair();
		}catch(Exception e){
			logger.error("export keypair error");
			e.printStackTrace();
			return null;
		}
		
		byte[] res = null;
		try{
			PKCS10CertificationRequest request = new PKCS10CertificationRequest(signalg, 
				new X509Name(dn), kp.getPublic(), null, kp.getPrivate());
			byte[] buf = request.getDEREncoded();//生成p10的der编码
			res = Base64.encode(buf);//进行base64编码
		}catch(Exception e){
			logger.error("generate p10 error");
			e.printStackTrace();
			return null;
		}
		return res;
	}
	
	/**
	 * 根据p10生成证书
	 * @param p10 P10格式的证书字节数组
	 * @param prikey 私钥
	 * @param signalg 签名算法
	 * @return 证书
	 */
	public X509Certificate CreateCert(byte[] p10, PrivateKey prikey, String signalg)
	{
		long currTime = new Date().getTime();      
        //证书生成   
        X509V3CertificateGenerator v3CertGen = new X509V3CertificateGenerator();   
        //序列号   
        int sel = (int)(new Date().getTime() / 1000L);
        Integer isel = new Integer(sel);
        String ssel = isel.toString();
        BigInteger bsel = new BigInteger(ssel);
        v3CertGen.setSerialNumber(bsel);

        //发行人
        String dn = "C=CN,ST=SD,L=WH,O=fisherman,OU=JMJ,CN=CA";
        v3CertGen.setIssuerDN(new X509Name(dn)); 
        //开始时间和结束时间  
        Calendar cal=Calendar.getInstance();
        cal.setTime(new Date(currTime));
        cal.add(Calendar.DATE, 365);
        
        v3CertGen.setNotBefore(new Date(currTime));   
        v3CertGen.setNotAfter(cal.getTime());   
        
        //签名算法        
        v3CertGen.setSignatureAlgorithm(signalg);   
		
        //从p10请求中获取公钥
        PKCS10CertificationRequest request = null;
        try{
        	request = new PKCS10CertificationRequest(p10);
        }catch(Exception e){
        	byte[] tmp = Base64.decode(p10);
        	request = new PKCS10CertificationRequest(tmp);
        }
      //主题   
        X509Name sj = request.getCertificationRequestInfo().getSubject();
        v3CertGen.setSubjectDN(sj);   
        try{
        	v3CertGen.setPublicKey(request.getPublicKey());
        }catch(Exception e){
        	logger.error("p10 request error");
        	e.printStackTrace();
        	return null;
        }
        
        //设置密钥用途
        //1<<7                                                      1<<6
        int   keyUsage = 0 | fisher.man.asn1.x509.KeyUsage.digitalSignature | fisher.man.asn1.x509.KeyUsage.nonRepudiation;
        v3CertGen.addExtension(X509Extensions.KeyUsage, false,
				new fisher.man.asn1.x509.KeyUsage(keyUsage));
        
        X509Certificate cert = null;
        try{
        	cert = v3CertGen.generate(prikey, "FishermanJCE");
        }catch(Exception e){
        	logger.error("gen cert error");
        	e.printStackTrace();
        	return null;
        }
        return cert; 
	}
}
