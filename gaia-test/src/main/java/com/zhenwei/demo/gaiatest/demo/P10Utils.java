package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.asn1.ASN1EncodableVector;
import cn.org.bjca.gaia.asn1.ASN1ObjectIdentifier;
import cn.org.bjca.gaia.asn1.ASN1Primitive;
import cn.org.bjca.gaia.asn1.ASN1Sequence;
import cn.org.bjca.gaia.asn1.ASN1Set;
import cn.org.bjca.gaia.asn1.DERBitString;
import cn.org.bjca.gaia.asn1.DERNull;
import cn.org.bjca.gaia.asn1.DERSet;
import cn.org.bjca.gaia.asn1.DERUTF8String;
import cn.org.bjca.gaia.asn1.gm.GMObjectIdentifiers;
import cn.org.bjca.gaia.asn1.pkcs.Attribute;
import cn.org.bjca.gaia.asn1.pkcs.CertificationRequest;
import cn.org.bjca.gaia.asn1.pkcs.CertificationRequestInfo;
import cn.org.bjca.gaia.asn1.pkcs.PKCSObjectIdentifiers;
import cn.org.bjca.gaia.asn1.x500.X500Name;
import cn.org.bjca.gaia.asn1.x509.AlgorithmIdentifier;
import cn.org.bjca.gaia.asn1.x509.SubjectPublicKeyInfo;
import cn.org.bjca.gaia.asn1.x9.X9ObjectIdentifiers;
import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.constant.AlgConstant;
import cn.org.bjca.gaia.assemb.exception.ErrorCode.Pkcs10;
import cn.org.bjca.gaia.assemb.exception.ErrorCode.Provider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.param.BjcaKeyPair;
import cn.org.bjca.gaia.assemb.param.SM3Param;
import cn.org.bjca.gaia.assemb.security.Gaia;
import cn.org.bjca.gaia.assemb.util.ASN1Util;
import cn.org.bjca.gaia.assemb.util.KeyPairUtil;
import cn.org.bjca.gaia.util.encoders.Base64;
import java.util.Iterator;
import java.util.Map;

public class P10Utils {

  private GaiaProvider provider = null;


  public P10Utils(GaiaProvider provider) {
    this.provider = provider;
  }

  public static void main(String[] args) throws Exception {
    Gaia instance = Gaia.getInstance();
    instance.initProvider(Gaia.BJCA_JE_PROVIDER);
    GaiaProvider provider = instance.openProvider(Gaia.BJCA_JE_PROVIDER);
    P10Utils p10Utils = new P10Utils(provider);

    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.SM2), 256);
    System.out.println(Base64.toBase64String(bjcaKeyPair.getPublicKey().getKey()));
    System.out.println(Base64.toBase64String(bjcaKeyPair.getPrivateKey().getKey()));
    //算法,主题项,扩展项,公钥,私钥,签名密钥索引,签名算法
    String p10 = p10Utils.generatorP10("SM2", "CN=test,C=CN", null,
        bjcaKeyPair.getPublicKey(), bjcaKeyPair.getPrivateKey());
    System.out.println("===p10:"+p10);

  }




  /**
   * 方法描述;产生证书请求
   *
   * @param alg 算法 ，支持RSA、SM2
   * @param dn 证书主题
   * @param extension 证书扩展项
   * @param bPublicKey 公钥
   * @param bPrivateKey 私钥
   * @return 证书请求
   * @author wangchuntao
   */
  public String generatorP10(String alg, String dn, Map extension, BjcaKey bPublicKey,
     BjcaKey bPrivateKey) throws Exception {
    if (! alg.equals(AlgConstant.RSA) &&
        !alg.equals(AlgConstant.SHA1_WITH_RSA) &&
        !alg.equals(AlgConstant.SHA256_WITH_RSA) &&
        !alg.equals(AlgConstant.SM2)){
      throw new PkiException(Pkcs10.GEN_P10,
          Pkcs10.GEN_P10_DES + " " +
              Provider.NOT_SUP_ALG_DES + " alg =" + alg);
    }
    String p10 = null;
    ASN1Set extentionSet = null;
    if (extension != null && extension.size() > 0) {
      ASN1EncodableVector v = new ASN1EncodableVector();
      Iterator iter = extension.entrySet().iterator();
      while (iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        String oid = (String) entry.getKey();
        String value = (String) entry.getValue();
        ASN1ObjectIdentifier derOid = new ASN1ObjectIdentifier(oid);
        DERUTF8String oidValue = new DERUTF8String(value);
        ASN1Set asn1Set = new DERSet(oidValue);
        Attribute att = new Attribute(derOid, asn1Set);
        v.add(att);
      }
      extentionSet = new DERSet(v);
    }

    if (alg.contains(AlgConstant.RSA)) {
     throw new Exception("暂不支持");
    } else {
      p10 = sm2P10Generator(dn, extentionSet, bPublicKey, bPrivateKey);
    }
    return p10;
  }

  private String rsaP10Generator(String alg, String dn, ASN1Set extension, BjcaKey pubKey,
      BjcaKey privateKey)
      throws PkiException {
    String base64P10 = null;
    String hashAlg = AlgPolicy.SHA1;
    String signAlg = AlgPolicy.SHA1_RSA;
    if (alg.equals(AlgPolicy.SHA1_RSA) || alg.equals(AlgPolicy.SHA256_RSA)) {
      hashAlg = AlgConstant.convertSignAlgToHashAlg(alg);
      signAlg = alg;
    }
    try {
      // 证书请求信息
      CertificationRequestInfo certReqInfo = semsRsaP10Generator(dn, extension, pubKey);
      // 将证书请求信息转换成byte[]
      byte[] bReqInfo = certReqInfo.getEncoded("DER");

      AlgPolicy hashPolicy = new AlgPolicy(hashAlg);
      byte[] hash = provider.hash(hashPolicy, bReqInfo);
      AlgPolicy signPolicy = new AlgPolicy(signAlg);
      byte[] derSign = provider.signHashedData(signPolicy, hash, privateKey);

      // 组装P10
      AlgorithmIdentifier signId = new AlgorithmIdentifier(
          PKCSObjectIdentifiers.sha1WithRSAEncryption, DERNull.INSTANCE);
      CertificationRequest certReq = new CertificationRequest(certReqInfo, signId,
          new DERBitString(derSign));
      // 将P10转换成byte[]
      byte[] bP10 = certReq.getEncoded("DER");
      base64P10 = new String(Base64.encode(bP10));
    } catch (Exception e) {
      throw new PkiException(Pkcs10.GEN_P10,
          Pkcs10.GEN_P10_DES, e);
    }
    return base64P10;
  }

  private CertificationRequestInfo semsRsaP10Generator(String dn, ASN1Set extension, BjcaKey pubKey)
      throws PkiException {
    CertificationRequestInfo certReqInfo = null;
    try {
      ASN1Sequence seq = (ASN1Sequence) ASN1Primitive.fromByteArray(pubKey.getKey());
      // 主题信息
      X500Name subject = new X500Name(dn);
      // 证书请求信息
      certReqInfo = new CertificationRequestInfo(subject,
          SubjectPublicKeyInfo.getInstance(seq), extension);
    } catch (Exception e) {
      throw new PkiException(Pkcs10.GEN_P10,
          Pkcs10.GEN_P10_DES, e);
    }
    return certReqInfo;
  }


  private String sm2P10Generator(String dn, ASN1Set extension, BjcaKey pubKey,
      BjcaKey privateKey) throws PkiException {
    String base64P10 = null;
    try {
      // 将证书请求信息转换成byte[]
      CertificationRequestInfo certReqInfo = semsSm2P10Generator(dn, extension, pubKey);
      byte[] bReqInfo = certReqInfo.getEncoded();
      //签名
      //签名
      SM3Param sm3Param = new SM3Param(pubKey.getKey());
      AlgPolicy hashPolicy = new AlgPolicy(AlgPolicy.SM3, sm3Param);
      byte[] hash = provider.hash(hashPolicy, bReqInfo);
      AlgPolicy signPolicy = new AlgPolicy(AlgPolicy.SM3_SM2);
      byte[] derSign = provider.signHashedData(signPolicy, hash, privateKey);

      // 组装P10
      AlgorithmIdentifier signAlg = new AlgorithmIdentifier(
          GMObjectIdentifiers.sm2sign_with_sm3);
      CertificationRequest certReq = new CertificationRequest(certReqInfo, signAlg,
          new DERBitString(derSign));
      // 将P10转换成byte[]
      byte[] bP10 = certReq.getEncoded("DER");
      base64P10 = new String(Base64.encode(bP10));
    } catch (Exception e) {
      throw new PkiException(Pkcs10.GEN_P10,
          Pkcs10.GEN_P10_DES, e);
    }
    return base64P10;
  }

  private CertificationRequestInfo semsSm2P10Generator(String dn, ASN1Set extension, BjcaKey pubKey)
      throws PkiException {
    CertificationRequestInfo certReqInfo = null;
    try {
      byte[] bPubKey = pubKey.getKey();
      // 算法标识
      AlgorithmIdentifier keyAlg = new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey,
          GMObjectIdentifiers.sm2p256v1);
      // 主题公钥信息
      SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo(keyAlg, bPubKey);
      // 主题信息
      X500Name subject = new X500Name(dn);
      // 证书请求信息
      certReqInfo = new CertificationRequestInfo(subject, spki, extension);
    } catch (Exception e) {
      throw new PkiException(Pkcs10.GEN_P10,
          Pkcs10.GEN_P10_DES, e);
    }
    return certReqInfo;
  }

  public byte[] semsP10(String alg, String dn, Map extension, BjcaKey bPublicKey)
      throws PkiException {
    if (! alg.equals(AlgConstant.RSA) &&
        !alg.equals(AlgConstant.SHA1_WITH_RSA) &&
        !alg.equals(AlgConstant.SHA256_WITH_RSA) &&
        !alg.equals(AlgConstant.SM2)){
      throw new PkiException(Pkcs10.GEN_P10,
          Pkcs10.GEN_P10_DES + " " +
              Provider.NOT_SUP_ALG_DES + " alg =" + alg);
    }
    byte[] p10 = null;
    CertificationRequestInfo certReqInfo = null;
    ASN1Set extentionSet = null;
    if (extension != null && extension.size() > 0) {
      ASN1EncodableVector v = new ASN1EncodableVector();
      Iterator iter = extension.entrySet().iterator();
      while (iter.hasNext()) {
        Map.Entry entry = (Map.Entry) iter.next();
        String oid = (String) entry.getKey();
        String value = (String) entry.getValue();
        ASN1ObjectIdentifier derOid = new ASN1ObjectIdentifier(oid);
        DERUTF8String oidValue = new DERUTF8String(value);
        ASN1Set asn1Set = new DERSet(oidValue);
        Attribute att = new Attribute(derOid, asn1Set);
        v.add(att);
      }
      extentionSet = new DERSet(v);
    }
    try {
      if (alg.contains(AlgConstant.RSA)) {
        certReqInfo = semsRsaP10Generator(dn, extentionSet, bPublicKey);
      } else if (AlgConstant.SM2.equals(alg)) {
        certReqInfo = semsSm2P10Generator(dn, extentionSet, bPublicKey);
      }
      if (certReqInfo == null){
        throw new PkiException(Pkcs10.GEN_P10,
            Pkcs10.GEN_P10_DES +" certReqInfo is null ");
      }
      p10 = certReqInfo.getEncoded("DER");
    } catch (Exception e) {
      throw new PkiException(Pkcs10.GEN_P10,
          Pkcs10.GEN_P10_DES, e);
    }
    return p10;
  }

  public static BjcaKey getP10PublicKey(String p10) throws PkiException {
    BjcaKey bPubKey = null;
    try {
      CertificationRequest certReq = CertificationRequest
          .getInstance(ASN1Util.checkAndGetASN1Object(Base64.decode(p10)));
      // 获得P10里的公钥
      SubjectPublicKeyInfo spki = certReq.getCertificationRequestInfo().getSubjectPublicKeyInfo();
      bPubKey = KeyPairUtil.subjectPubKeyInfo2Key(spki);
    } catch (Exception e) {
      throw new PkiException(Pkcs10.PARSE_PUBLIC,
          Pkcs10.PARSE_PUBLIC_DES, e);
    }
    return bPubKey;
  }

  public static String getP10DN(String p10) throws PkiException {
    // 构造P10对象
    String dn = null;
    try {
      CertificationRequest certReq = CertificationRequest
          .getInstance(ASN1Util.checkAndGetASN1Object(Base64.decode(p10)));
      dn = certReq.getCertificationRequestInfo().getSubject().toString();
    } catch (Exception e) {
      throw new PkiException(Pkcs10.PARSE_DN,
          Pkcs10.PARSE_DN_DES, e);
    }
    return dn;
  }

  public static void checkDN(String dn) throws PkiException {
    try {
      new X500Name(dn);
    }catch (Exception e){
     throw new PkiException(Pkcs10.CHECK_DN,
          Pkcs10.CHECK_DN_DES, e);
    }
  }

}
