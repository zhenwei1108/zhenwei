package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.cloud.ca.pki.common.util.KeyUtils;
import cn.org.bjca.gaia.asn1.ASN1Sequence;
import cn.org.bjca.gaia.asn1.DEROctetString;
import cn.org.bjca.gaia.asn1.DLSequence;
import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.param.BjcaKeyPair;
import cn.org.bjca.gaia.assemb.util.ASN1Util;
import cn.org.bjca.gaia.assemb.util.KeyPairUtil;
import cn.org.bjca.gaia.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import cn.org.bjca.gaia.jce.provider.BJCAJEProvider;
import cn.org.bjca.gaia.util.encoders.Base64;
import cn.org.bjca.soft.asn1.x509.SubjectPublicKeyInfo;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import org.bjca.jce.provider.asymmetric.ec.KeyPairGenerator;
import org.junit.Test;

public class KeyPairTest {

  static {
    Security.addProvider(new BJCAJEProvider());
  }

  public static void main(String[] args) throws Exception {

  }

  @Test
  public void genSm2KeyPair() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.SM2), 256);
    BjcaKey publicKey = bjcaKeyPair.getPublicKey();
    System.out.println(Base64.toBase64String(publicKey.getKey()));
  }


  @Test
  public void testSM2EncByIndex() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    BjcaKey sm2Pub = new BjcaKey(BjcaKey.SM2_PUB_KEY, 1);
    BjcaKey sm2Pri = new BjcaKey(BjcaKey.SM2_PRV_KEY, 1);
    byte[] encrypt = provider
        .encrypt(new AlgPolicy(AlgPolicy.SM2), sm2Pub, "123123asdf".getBytes());
    byte[] decrypt = provider.decrypt(new AlgPolicy(AlgPolicy.SM2), sm2Pri, encrypt);
    System.out.println(new String(decrypt));
  }

  @Test
  public void testRsaEncByIndex() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    BjcaKey rsaPub = new BjcaKey(BjcaKey.RSA_PUB_KEY, 1);
    BjcaKey rsaPri = new BjcaKey(BjcaKey.RSA_PRV_KEY, 1);
    byte[] encrypt = provider.encrypt(new AlgPolicy(AlgPolicy.RSA_ENC), rsaPub, "asdfasdf".getBytes());
    byte[] decrypt = provider.decrypt(new AlgPolicy(AlgPolicy.RSA_ENC), rsaPri, encrypt);
    System.out.println(new String(decrypt));

  }




  public static void genKeyPairSm2() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.SM2), 256);
    BjcaKey publicKey = bjcaKeyPair.getPublicKey();
    System.out.println(Base64.toBase64String(publicKey.getKey()));
    BjcaKey privateKey = bjcaKeyPair.getPrivateKey();
    System.out.println(Base64.toBase64String(privateKey.getKey()));
  }

  @Test
  public void genKeyPairRSA() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.RSA), 1024);
    byte[] key = bjcaKeyPair.getPrivateKey().getKey();
    byte[] p1Key = KeyPairUtil.convertRsaP8PriKeyToP1(key);
    System.out.println(p1Key.length);

    PublicKey rsaPub = KeyPairUtil.convertPublicKey(bjcaKeyPair.getPublicKey());
    PrivateKey rsaPri = KeyPairUtil.convertPrivateKey(bjcaKeyPair.getPrivateKey());
    KeyPair keyPair = new KeyPair(rsaPub, rsaPri);

    BjcaKey bjcaKeyPub = KeyPairUtil.subjectPubKeyInfo2Key(keyPair.getPublic().getEncoded());

    byte[] bytesRsaPri = KeyPairUtil.convertRsaP8PriKeyToP1(keyPair.getPrivate().getEncoded());
    BjcaKey bjcaKeyPri = new BjcaKey(BjcaKey.RSA_PRV_KEY, bytesRsaPri);
    bjcaKeyPair = new BjcaKeyPair(bjcaKeyPub, bjcaKeyPri);

    byte[] encryptData = provider.encrypt(new AlgPolicy(AlgPolicy.RSA_ENC), bjcaKeyPub, "asfd".getBytes());
    byte[] decrypt = provider.decrypt(new AlgPolicy(AlgPolicy.RSA_ENC), bjcaKeyPri, encryptData);
    System.out.println(new String(decrypt));

    System.out.println(bjcaKeyPair);
  }


  public static void test() throws PkiException {
    String pub = "I83E5enlbVNRmL6194dV0Ti+uhOMVwE4uWiBOKwPDJgWmqSIwdoXVUKwNkVMtJyOUNitq9AFxzFZyqv7x+Iw1zcUWJq9WAGTaVooSgSGcudaqSpf1bcYuBGxlE==";
    BjcaKey bjcaKey = KeyPairUtil.subjectPubKeyInfo2Key(Base64.decode(pub));
    byte[] key = bjcaKey.getKey();
    String s = Base64.toBase64String(key);
    System.out.println(s);

  }

  public static void testKey() throws Exception {

    java.security.KeyPairGenerator generator = KeyPairGenerator.getInstance("EC","BJCAJE");
    generator.initialize( new ECGenParameterSpec("sm2p256v1"));
    KeyPair keyPair = generator.generateKeyPair();
    byte[] priKeyEncoded = keyPair.getPrivate().getEncoded();
    priKeyEncoded = Base64.decode(
        "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgouQUXqkSnwNI6vbAEeNezq8oxcGJ4lgKrzNrnx7uoyWgCgYIKoEcz1UBgi2hRANCAARaN0DI2N6rgqaZf2G8A4J6gDro4a72KIobH5on0dWbO7rzyBCeqYZCL7/Ls+AKJp763cVrwLip8+Gpxx+9Cq4i");
    System.out.println(priKeyEncoded.length);
    System.out.println(Base64.toBase64String(priKeyEncoded));


    byte[] bytes = ((BCECPrivateKey) keyPair.getPrivate()).getD().toByteArray();

    ASN1Sequence asn1Object = (ASN1Sequence)ASN1Util.checkAndGetASN1Object(priKeyEncoded);

    DLSequence dlSequence = (DLSequence) DLSequence.fromByteArray(priKeyEncoded);
    byte[] priKeys = ((DEROctetString) dlSequence.getObjectAt(2)).getOctets();
    dlSequence = (DLSequence) DLSequence.fromByteArray(priKeys);
    DEROctetString derPriKey = (DEROctetString) dlSequence.getObjectAt(1);
    BjcaKey bjcaKey = new BjcaKey(BjcaKey.SM2_PRV_KEY, derPriKey.getOctets());
    System.out.println(Base64.toBase64String(bjcaKey.getKey()));
  }

  @Test
  public void convertKey() throws PkiException {
//    String cossPubkey="MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEUrN4h3CfpCQC45v9U0crh2c/GB601r9mSnJ6d2ED+g9cGR1yIb3wTcthrlyc2Yf5JNJtrQUv53wBzlY0XNjGw==";
//    byte[] cossPubkeyDec = Base64.decode(cossPubkey);
//    BjcaKey bjcyes
//    aKey = KeyPairUtil.subjectPubKeyInfo2Key(cossPubkeyDec);
    String gaiaPubkey ="L8qGgmA2GnVkOrP35Sqkpm1/9Uic/cJEYinNmNWRubQ4uJz5hoshZT273YKEdGLQZxrcP+GJrVwF8MOXTNzMag==";
    BjcaKey bjcaKey = new BjcaKey(BjcaKey.SM2_PUB_KEY, Base64.decode(gaiaPubkey));
    System.out.println(Base64.toBase64String(bjcaKey.getKey()));

    PublicKey publicKey = KeyPairUtil.convertPublicKey(bjcaKey);

    System.out.println(Base64.toBase64String(publicKey.getEncoded()));

  }


  //----------
  @Test
  public void testSm2Key() throws IOException {
    String gaiaPubkey ="L8qGgmA2GnVkOrP35Sqkpm1/9Uic/cJEYinNmNWRubQ4uJz5hoshZT273YKEdGLQZxrcP+GJrVwF8MOXTNzMag==";
    byte[] decode = Base64.decode(gaiaPubkey);
    decode = getDerPublickey(decode);
    SubjectPublicKeyInfo sm2SubPubkeyInfo = KeyUtils.getSM2SubPubkeyInfo(decode);
    byte[] encoded = sm2SubPubkeyInfo.getEncoded();
    System.out.println(encoded.length);
    System.out.println(sm2SubPubkeyInfo);

  }

  public static byte[] getDerPublickey(byte[] publicKey) {
    if (publicKey.length == 65) {
      return publicKey;
    } else {
      byte[] pubKey = new byte[65];
      byte[] first = new byte[]{4};
      System.arraycopy(first, 0, pubKey, 0, 1);
      System.arraycopy(publicKey, 0, pubKey, 1, 64);
      return pubKey;
    }
  }



}
