import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertStore;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;

import fisher.man.asn1.ASN1InputStream;
import fisher.man.asn1.ASN1Sequence;
import fisher.man.asn1.x509.SubjectKeyIdentifier;
import fisher.man.asn1.x509.SubjectPublicKeyInfo;
import fisher.man.cms.CMSEnvelopedData;
import fisher.man.cms.CMSEnvelopedDataGenerator;
import fisher.man.cms.CMSEnvelopedDataParser;
import fisher.man.cms.CMSEnvelopedGenerator;
import fisher.man.cms.CMSProcessable;
import fisher.man.cms.CMSProcessableByteArray;
import fisher.man.cms.CMSSignedData;
import fisher.man.cms.CMSSignedDataGenerator;
import fisher.man.cms.CMSSignedDataParser;
import fisher.man.cms.CMSSignedGenerator;
import fisher.man.cms.CMSTypedStream;
import fisher.man.cms.RecipientInformation;
import fisher.man.cms.RecipientInformationStore;
import fisher.man.cms.SignerInformation;
import fisher.man.cms.SignerInformationStore;
import fisher.man.util.encoders.Base64;


public class FMP7 {
	Logger logger = Logger.getLogger(FMP7.class);
	String sAlias = "p7";
	/**
	 * p7数字信封测试
	 * @param p7path 生成的P7信封文件路径
	 * @param certpath 证书文件路径
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public void P7BEnvCertTest(String p7path,String certpath,boolean isRSA,int keybits,boolean isBase64){
		int rv = 0;
		/*********P7生成临时证书，并存入keystore中，别名为p7***********/
		rv = TempCert(p7path, certpath, isRSA, keybits);
		if(rv!=0){
			logger.error("write cert to keystore error");
			return;
		}
		
		String encdata = "12345678";
		/*********生成P7数字信封***********/
		rv = GenEnvData(certpath, encdata, p7path, isBase64);
		if(rv!=0){
			logger.error("gen p7 envelop file error");
			return;
		}else{
			logger.info("gen p7 envelop file ok！");
		}
		/*********P7数字信封拆封***********/
		String decdata = RecEnvData(p7path, isBase64);
		/*********对比拆封数据与源数据是否相同***********/
		if(encdata.equalsIgnoreCase(decdata)){
			logger.info("decode p7 envelop file ok");
		}else{
			logger.error("decode p7 envelop file error");
			return;
		}
	}
	
	/**
	 * P7数字签名验签测试
	 * @param p7path 生成的P7签名文件路径
	 * @param certpath 证书文件路径
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public void P7BSignCertTest(String p7path,String certpath,boolean isRSA,int keybits,boolean isBase64){
		int rv = 0;
		/*********P7生成临时证书，并存入keystore中，别名为p7***********/
		rv = TempCert(p7path, certpath, isRSA, keybits);
		if(rv!=0){
			logger.error("write cert to keystore error");
			return;
		}
		
		String signdata = "12345678";
		boolean encapsulate = true;//true包含明文attach模式，false不包含明文detach模式
		/*********生成P7数字签名***********/
		rv = GenSignData(signdata, encapsulate, certpath, p7path, isBase64);
		if(rv!=0){
			logger.error("gen p7 sign file error");
			return;
		}else{
			logger.info("gen p7 sign file ok！");
		}
		/*********P7数字签名验签***********/
		rv = RecSignData(p7path, encapsulate, signdata, isBase64);
		if(rv!=0){
			logger.error("p7 sign file verify error");
			return;
		}else{
			logger.info("p7 sign file verify ok");
		}
	}
	
	/**
	 * 生成P7的临时证书文件，并存储到keystore中，别名为envp7
	 * @param p7path 生成的P7信封文件路径
	 * @param certpath 证书文件路径
	 * @param isRSA 测试程序是否以RSA算法为例。true为RSA算法，false为SM2算法
	 * @param keybits 算法长度。RSA为1024或2048，SM2为256
	 */
	public int TempCert(String p7path,String certpath,boolean isRSA,int keybits){
		int ret = 0;
		KeyPair kpair = null;
		if(isRSA){
			FMRsa rsa = new FMRsa();
			kpair = rsa.ExportInternalRSAKeyPair(1, keybits);
		}else{
			FMSM2 sm2 = new FMSM2();
			kpair = sm2.ExportInternalSM2KeyPair(1);			
		}
		
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime() + 3650 * 24 * 60 * 60 * 1000L);
		X509Certificate usrcert = null;
		try {
			usrcert = FMCert.CreateX509Certificate(true, 
					false, 
					kpair.getPublic(), 
					"C=CN,ST=SD,L=WH,O=fisherman,OU=JMJ,CN=CA",
					notBefore,
					notAfter,
					null, 
					kpair.getPrivate(), 
					isRSA,//isRSA
					false);
		} catch (Exception e) {
			logger.error("gen p7 temp cert file error");
			e.printStackTrace();
			return -1;
		}
		
		 try{
			byte[] buffer  = usrcert.getEncoded();
	        BufferedOutputStream outputStream = new BufferedOutputStream(new FileOutputStream(new File(certpath)));
	        outputStream.write(buffer);
	        outputStream.flush();
	        outputStream.close();
		}catch(Exception e){
			logger.error("write p7 temp cert file error");
			return -1;
		}
		try{
			KeyStore keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
	        keyStore.load(null, "12345678".toCharArray());
	        // 证书链
	        X509Certificate[] certs = new X509Certificate[1];
	        certs[0] = usrcert;
	
	        // 设置私钥和通信证书
	        KeyStore.PrivateKeyEntry commEntry = new KeyStore.PrivateKeyEntry(kpair.getPrivate(), certs);
	        keyStore.setEntry(sAlias, commEntry, new KeyStore.PasswordProtection("12345678".toCharArray()));
	        keyStore.store(null, "12345678".toCharArray());
		}catch(Exception e){
			logger.error("write cert to keystore error");
			e.printStackTrace();
			return -1;
		}
		return ret;
	}

	/**
	 * 封装P7数字信封
	 * @param file证书路径
	 * @param encdata打包数据
	 * @param path数字信封路径
	 */
    public int GenEnvData(String file,String encdata,String path,boolean isBase64){
    	int ret = 0;
        PublicKey pubkey=null;
        try {
            FileInputStream fis = new FileInputStream(file);
            int fl=fis.available();
            byte[] buf = new byte[fl];
            fis.read(buf);
            ByteArrayInputStream bs = new ByteArrayInputStream(buf);
            CertificateFactory cf = CertificateFactory.getInstance("X.509","FishermanJCE");
            X509Certificate cert = (X509Certificate) cf.generateCertificate(bs);
            bs.close();
            fis.close();
            //获得公钥和公钥算法
            pubkey = cert.getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
        	logger.error("read p7 cert error");
            return -1;
        }

        byte[] subKeyId = null;
        try{
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(pubkey.getEncoded())).readObject());
            SubjectKeyIdentifier rett = new fisher.man.asn1.x509.SubjectKeyIdentifier(spki);
            subKeyId = rett.getKeyIdentifier();
        }catch(Exception e){
            e.printStackTrace();
        	logger.error("gen key id error");
            return -1;
        }

        //进行数字信封封装
        CMSProcessableByteArray content = new CMSProcessableByteArray(encdata.getBytes());
        CMSEnvelopedDataGenerator fact = new CMSEnvelopedDataGenerator();
        fact.addKeyTransRecipient(pubkey, subKeyId);
        try{
            CMSEnvelopedData data = fact.generate(content, CMSEnvelopedGenerator.SM4_CBC, "FishermanJCE");//SM1_ECB
            byte[] outdata = null;
            if(isBase64){
            	byte[] outdata1 = data.getEncoded();
                outdata = Base64.encode(outdata1);
            }else{
            	outdata = data.getEncoded();
            }
            FileOutputStream fileOut = new FileOutputStream(path);
            DataOutputStream localDataOutputStream = new DataOutputStream(fileOut);
            localDataOutputStream.write(outdata);
            localDataOutputStream.close();
            fileOut.flush();
            fileOut.close();
        }catch(Exception e){
            e.printStackTrace();
        	logger.error("gen p7 envelop file error");
            return -1;
        }
       return ret;
    }

	/**
	 * 拆封P7数字信封
	 * @param path为P7数字信封路径
	 * @return 打包的数据
	 */
    @SuppressWarnings("unchecked")
	public String RecEnvData(String path,boolean isBase64){
        //从keystore中获取私钥
        KeyStore keyStore = null;
		PrivateKey key = null;
        try {
            keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
            keyStore.load(null, "12345678".toCharArray());
        } catch (Exception ex) {
        	logger.error("keystore load error");
            return null;
        }

        byte[] p7Data = null;
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream(path);
            int dataLen = fis.available();
            if(isBase64){
            	byte[] certdata = new byte[dataLen];
                if ((fis.read(certdata)) == -1) {
                	logger.error("read p7 file error");
                    fis.close();
                    return null;
                }
                p7Data = Base64.decode(certdata);
            }else{
            	p7Data = new byte[dataLen];
                if ((fis.read(p7Data)) == -1) {
                	logger.error("read p7 file error");
                    fis.close();
                    return null;
                }
            }
            fis.close();
        } catch (Exception e) {
        	logger.error("read p7 file error");
            e.printStackTrace();
            return null;
        }
        //进行解包
        byte[] decodedata = null;
        try {
            CMSEnvelopedDataParser ep = new CMSEnvelopedDataParser(p7Data);
            RecipientInformationStore recipients = ep.getRecipientInfos();
            Collection c = recipients.getRecipients(); //
            Iterator it = c.iterator(); //

            if (it.hasNext()) {
                RecipientInformation   recipient = (RecipientInformation)it.next();
                key = (PrivateKey) keyStore.getKey(sAlias, "12345678".toCharArray());
                if(key==null){
                	logger.error("gen key from keystore error");
                    return null;
                }

                CMSTypedStream recData = recipient.getContentStream(key, "FishermanJCE");
                byte[] buffer = new byte[1024];
                byte[] tmp = new byte[4096];

                int i = 0, offset = 0;
                while((i=recData.getContentStream().read(buffer)) != -1) {
                    System.arraycopy(buffer, 0, tmp, offset, i);
                    offset += i;
                }
                decodedata = new byte[offset];
                System.arraycopy(tmp, 0, decodedata, 0, offset);
            }
        } catch (Exception e1) {
            e1.printStackTrace();
        	logger.error("p7 decode error");
            return null;
        }
        return new String(decodedata);
    }
    
	/**
	 * P7数字签名生成
	 * @param signdata要签名的数据
	 * @param encapsulate 模式 true包含明文attach模式，false不包含明文detach模式
	 * @param file是数字证书路径
	 * @param path是数字签名保存路径
	 */
    public int GenSignData(String signdata,boolean encapsulate,String file,String path,boolean isBase64){
    	int ret = 0;
        //从keystore中获取私钥
        KeyStore keyStore = null;
		PrivateKey key = null;
        try {
            keyStore = KeyStore.getInstance("FMKS", "FishermanJCE");
            keyStore.load(null, "12345678".toCharArray());
        } catch (Exception ex) {
        	logger.error("keystore load error");
            return -1;
        }

        X509Certificate cert = null;
        try {
            FileInputStream fis = new FileInputStream(file);
            int fl=fis.available();
            byte[] buf = new byte[fl];
            fis.read(buf);
            ByteArrayInputStream bs = new ByteArrayInputStream(buf);
            CertificateFactory cf = CertificateFactory.getInstance("X.509","FishermanJCE");
            cert = (X509Certificate) cf.generateCertificate(bs);
            bs.close();
            fis.close();
        } catch (Exception e) {
            e.printStackTrace();
        	logger.error("read p7 cert error");
            return -1;
        }
        
        try {
                key = (PrivateKey) keyStore.getKey(sAlias, "12345678".toCharArray());
        } catch (Exception ex) {
        	logger.error("gen key from keystore error");
            return -1;
        }
        if(key==null){
        	logger.error("gen key from keystore error");
            return -1;
        }

        CertStore certs = null;
        CMSSignedData data=null;
        List<X509Certificate> certlist= new ArrayList<X509Certificate>();
        try{
            certlist.add(cert);
            certs=CertStore.getInstance("Collection", new CollectionCertStoreParameters(certlist), "FishermanJCE");
            CMSSignedDataGenerator    gen = new CMSSignedDataGenerator();
            if(key.getAlgorithm().equalsIgnoreCase("RSA")){
            	gen.addSigner(key, cert, CMSSignedGenerator.DIGEST_SHA1);
            }
            if(key.getAlgorithm().equalsIgnoreCase("SM2")){
            	gen.addSigner(key, cert, CMSSignedGenerator.DIGEST_SM3);
            }
            gen.addCertificatesAndCRLs(certs);
            CMSProcessable content = new CMSProcessableByteArray(signdata.getBytes());
            data = gen.generate(CMSSignedDataGenerator.DATA,content,encapsulate, "FishermanJCE");
        }catch(Exception e){
            e.printStackTrace();
        	logger.error("gen p7 sign data error");
            return -1;
        }
        try{
        	byte[] outdata = null;
            if(isBase64){
            	byte[] outdata1 = data.getEncoded();
                outdata = Base64.encode(outdata1);
            }else{
            	outdata = data.getEncoded();
            }
            FileOutputStream fileOut = new FileOutputStream(path);
            DataOutputStream localDataOutputStream = new DataOutputStream(fileOut);
            localDataOutputStream.write(outdata);
            localDataOutputStream.close();
            fileOut.flush();
            fileOut.close();
        }catch(Exception e){
        	e.printStackTrace();
        	logger.error("write p7 sign file error");
            return -1;
        }
        return ret;
    }
    
    /**
     * P7数字签名验签
     * @param path 数字签名保存路径
     * @param encapsulate  签名模式，true为attach模式，false为detach模式，dettach模式下需要输入原始数据，即signdata
     * @param signdata 签名的数据
     */
    @SuppressWarnings("unchecked")
	public int RecSignData(String path,boolean encapsulate,String signdata,boolean isBase64){
    	int ret = 0;
        byte[] p7Data = null;
        try {
            java.io.FileInputStream fis = new java.io.FileInputStream(path);
            int dataLen = fis.available();
            if(isBase64){
            	byte[] certdata = new byte[dataLen];
                if ((fis.read(certdata)) == -1) {
                	logger.error("read p7 file error");
                    fis.close();
                    return -1;
                }
                p7Data = Base64.decode(certdata);
            }else{
            	p7Data = new byte[dataLen];
                if ((fis.read(p7Data)) == -1) {
                	logger.error("read p7 file error！");
                    fis.close();
                    return -1;
                }
            }
            fis.close();
        } catch (Exception e) {
        	logger.error("read p7 file error");
            e.printStackTrace();
            return -1;
        }
        try {
            CMSSignedDataParser sd = null;
            if(encapsulate){
                sd = new CMSSignedDataParser(p7Data);
            }else{
                sd = new CMSSignedDataParser(new CMSTypedStream(new ByteArrayInputStream(signdata.getBytes())),p7Data);
            }
            sd.getSignedContent().drain();
            CertStore certs = sd.getCertificatesAndCRLs("Collection", "FishermanJCE");
            SignerInformationStore  signers = sd.getSignerInfos();
            Collection c = signers.getSigners();
            Iterator it = c.iterator();

            while (it.hasNext()){
               SignerInformation signer = (SignerInformation)it.next();
	           Collection certCollection = certs.getCertificates(signer.getSID());
	           Iterator certIt = certCollection.iterator();
	           X509Certificate cert = (X509Certificate)certIt.next();
               boolean v = signer.verify(cert, "FishermanJCE");
               if(!v){
            	   ret = -1;
               }
	       }
        } catch (Exception ex) {
        	logger.error("p7 verify error！");
            ex.printStackTrace();
            return -1;
        }
        return ret;
    }
}
