import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.apache.log4j.Logger;

import fisher.man.asn1.ASN1InputStream;
import fisher.man.asn1.ASN1Sequence;
import fisher.man.asn1.x509.AuthorityKeyIdentifier;
import fisher.man.asn1.x509.BasicConstraints;
import fisher.man.asn1.x509.ExtendedKeyUsage;
import fisher.man.asn1.x509.KeyPurposeId;
import fisher.man.asn1.x509.KeyUsage;
import fisher.man.asn1.x509.SubjectKeyIdentifier;
import fisher.man.asn1.x509.SubjectPublicKeyInfo;
import fisher.man.asn1.x509.X509Extensions;
import fisher.man.asn1.x509.X509Name;
import fisher.man.x509.X509V3CertificateGenerator;

/**
 *用内部密钥产生p10请求、证书
 */
public class FMCert
{
	Logger logger = Logger.getLogger(FMCert.class);
	/**
	 * 证书测试
	 * @param path 生成证书的路径
	 * @param certkeyid 证书密钥ID
	 * @param cakeyid CA密钥ID
	 */
	public void Certtest(String path, int certkeyid, int cakeyid,boolean isRSA,int keybits){
		FMP10 p10 = new FMP10();
		if(isRSA){
			FMRsa rsa = new FMRsa();
			//产生证书请求
			byte[] p10data = p10.CreateP10Request("RSA", "SHA1withRSA", certkeyid, keybits, "C=CN,ST=SD,L=WH,O=fisherman,OU=JMJ,CN=test");
			if(p10 == null){
				logger.error("gen p10 error");
				return;
			}
			
			//导出cakeyid号密钥对用于签发证书及证书验证
			KeyPair kp = rsa.ExportInternalRSAKeyPair(cakeyid,keybits);
			if(kp == null){
				logger.error("export keypair error");
				return;
			}
			//用cakeyid号密钥私钥进行证书签发
			X509Certificate cert = p10.CreateCert(p10data, kp.getPrivate(), "SHA1withRSA");
			if(cert == null){
				logger.error("create cert error");
				return;
			}
			try{
				byte[] buffer  = cert.getEncoded();   
		        BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(new File(path)));   
		        outputStream.write(buffer);   
		        outputStream.flush();   
		        outputStream.close(); 
			}catch(Exception e){
				logger.error("write cert to file error");
				return;
			}
			//验证证书有效性
			try{
				cert.checkValidity();
				cert.verify(kp.getPublic());
			}catch(Exception e){
				logger.error("cert verify fail");
				e.printStackTrace();
				return;
			}
			
			//用certkeyid号私钥签名，生成的证书验证
			byte[] indata = new byte[100];
			for(int i = 0;i<indata.length;i++){
				indata[i] = (byte)i;
			}
			byte[] signdata = rsa.InternalRSASign("SHA1", certkeyid,keybits, indata);
			boolean rv = rsa.ExternalRSAVerify("SHA1", cert.getPublicKey(), indata, signdata);
			if(rv){
				logger.info("cert verify ok");
			}else{
				logger.error("cert verify error");
			}
		}else{
			FMSM2 sm2 = new FMSM2();
			//产生证书请求
			byte[] p10data = p10.CreateP10Request("SM2", "SM3withSM2", certkeyid, keybits, "C=CN,ST=SD,L=WH,O=fisherman,OU=JMJ,CN=test");
			if(p10 == null){
				logger.error("gen p10 error");
				return;
			}
			
			//导出cakeyid号密钥对用于签发证书及证书验证
			KeyPair kp = sm2.ExportInternalSM2KeyPair(cakeyid);
			if(kp == null){
				logger.error("export keypair error");
				return;
			}
			
			//用cakeyid号密钥私钥进行证书签发
			X509Certificate cert = p10.CreateCert(p10data, kp.getPrivate(), "SM3withSM2");
			if(cert == null){
				logger.error("create cert error");
				return;
			}
			try{
				byte[] buffer  = cert.getEncoded();   
		        BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(new File(path)));   
		        outputStream.write(buffer);   
		        outputStream.flush();   
		        outputStream.close(); 
			}catch(Exception e){
				logger.error("write cert to file error");
				return;
			}
			//验证证书有效性
			try{
				cert.checkValidity();
				cert.verify(kp.getPublic());
			}catch(Exception e){
				logger.error("cert verify fail");
//				e.printStackTrace();
				return;
			}
			
			//用certkeyid号私钥签名，生成的证书验证
			byte[] indata = new byte[100];
			for(int i = 0;i<indata.length;i++){
				indata[i] = (byte)i;
			}
			byte[] signdata = sm2.InternalSM2Sign("SM3withSM2", certkeyid, indata);
			boolean rv = sm2.ExternalSM2Verify("SM3withSM2", cert.getPublicKey(), indata, signdata);
			if(rv){
				logger.info("cert verify ok");
			}else{
				logger.error("cert verify error");
			}
		}
	}
	/**
	 * 创建证书
	 * @param selfSign 是否是CA证书
	 * @param isCa 是否是CA证书
	 * @param publicKey 用户公钥
	 * @param subjectDN 证书主题
	 * @param signCert	签名证书 可为null
	 * @param signPirv 签名私钥 与 签名证书 匹配 不能为null
	 * @param isRSA
	 * @return 证书
	 * @throws Exception
	 */
	public static X509Certificate CreateX509Certificate(boolean selfSign,boolean isCa,PublicKey publicKey,String subjectDN,Date notefore,Date notAfter,X509Certificate signCert,PrivateKey signPirv,boolean isRSA,boolean isTsa) throws Exception{
		
		//得到证书序列号
		BigInteger serialNumber = SernoGenerator.instance().getSerno();
		//v3证书生成信息设置
		X509V3CertificateGenerator v3CertGenerator = new X509V3CertificateGenerator();
		//序列号
		v3CertGenerator.setSerialNumber(serialNumber);
		//主题DN项
		v3CertGenerator.setSubjectDN(new X509Name(subjectDN));
		//颁发者DN项
		if(selfSign){
			v3CertGenerator.setIssuerDN((new X509Name(subjectDN)));
		}else{
			v3CertGenerator.setIssuerDN(new X509Name(signCert.getSubjectDN().getName()));
		}
		//证书有效期
		v3CertGenerator.setNotBefore(notefore);
		v3CertGenerator.setNotAfter(notAfter);
		//设置公钥信息
		v3CertGenerator.setPublicKey(publicKey);
		
		//设置签名算法
		if(isRSA){
			v3CertGenerator.setSignatureAlgorithm("SHA1WITHRSA");
		}else{
			v3CertGenerator.setSignatureAlgorithm("SM3WITHSM2");
		}
		
		//---------添加扩展信息---------
		//基本限制扩展
		BasicConstraints bc = new BasicConstraints(isCa);
		v3CertGenerator.addExtension(X509Extensions.BasicConstraints.getId(), true, bc);
		//主题密钥标示符
		ByteArrayInputStream ins = new ByteArrayInputStream(publicKey.getEncoded());
		ASN1InputStream dis = new ASN1InputStream(ins);
		
		SubjectPublicKeyInfo spk = new SubjectPublicKeyInfo((ASN1Sequence)dis.readObject());
		dis.close();
		ins.close();
		
		SubjectKeyIdentifier  sk = new SubjectKeyIdentifier(spk);
		v3CertGenerator.addExtension(X509Extensions.SubjectKeyIdentifier.getId(), false, sk);
		
		//颁发机构密钥标示符
		if(selfSign){
			ins = new ByteArrayInputStream(publicKey.getEncoded());
		}else{
			ins = new ByteArrayInputStream(signCert.getPublicKey().getEncoded());
		}
		
		dis = new ASN1InputStream(ins);
		 
		spk = new SubjectPublicKeyInfo((ASN1Sequence)dis.readObject());
		dis.close();
		ins.close();
		
		AuthorityKeyIdentifier ak = new AuthorityKeyIdentifier(spk);
		v3CertGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier.getId(), false, ak);
		
		if(!isCa){
			//密钥用途
			int keyU = 0;
			keyU = keyU | KeyUsage.nonRepudiation | KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.keyAgreement;
			KeyUsage ku = new KeyUsage(keyU);
			v3CertGenerator.addExtension(X509Extensions.KeyUsage.getId(), false, ku);
		}else{
			//密钥用途
			int keyU = 0;
			keyU = keyU | KeyUsage.cRLSign | KeyUsage.keyCertSign;
			KeyUsage ku = new KeyUsage(keyU);
			v3CertGenerator.addExtension(X509Extensions.KeyUsage.getId(), false, ku);
		}
		if(isTsa){
			ExtendedKeyUsage eku = new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping);
			v3CertGenerator.addExtension(X509Extensions.ExtendedKeyUsage, true, eku);
		}
		
		X509Certificate cert = v3CertGenerator.generate(signPirv, "FishermanJCE");	
		
		return cert;
	}
}