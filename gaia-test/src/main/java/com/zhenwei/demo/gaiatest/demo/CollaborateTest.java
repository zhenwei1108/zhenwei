//package com.zhenwei.demo.gaiatest.demo;
//
//import cn.org.bjca.gaia.assemb.base.GaiaProvider;
//import cn.org.bjca.gaia.assemb.collaborate.util.ASymUtil;
//import cn.org.bjca.gaia.assemb.collaborate.util.EncodeUtil;
//import cn.org.bjca.gaia.assemb.collaborate.util.SEMSM2Util;
//import cn.org.bjca.gaia.assemb.exception.PkiException;
//import cn.org.bjca.gaia.assemb.param.AlgPolicy;
//import cn.org.bjca.gaia.assemb.param.BjcaKey;
//import cn.org.bjca.gaia.assemb.param.BjcaKeyPair;
//import cn.org.bjca.gaia.assemb.param.SM3Param;
//import cn.org.bjca.gaia.assemb.security.Gaia;
//
///**
// * @description: //TODO  协同签名
// * @author: zhangzhenwei@bjca.org.cn
// * @Date 8:31 上午 2020/6/8
//*/
//public class CollaborateTest {
//
//  //待签名数据
//  static byte[] plain = "1234567890123456dsadsadsadsa".getBytes();
//  private static GaiaProvider provider;
//  static {
//    try {
//      provider = Gaia.getSingletonGaia(Gaia.BJCA_JE_PROVIDER);
//    } catch (PkiException e) {
//      e.printStackTrace();
//    }
//  }
//
//  public static void main(String[] args) throws Exception {
//    test();
//
//  }
//
//  //RSA协同签名
//  public static void testRsaSignVerify() throws Exception {
//    byte[] rr = buildPri();
//    //客户端私钥因子
//    byte[] cs = provider.hash(new AlgPolicy(AlgPolicy.SHA1), rr);
//
//    byte[][] genKey = ASymUtil.genRSAKeyPair(1024, cs);
//    //私钥因子
//    byte[] ss = genKey[0];
//
//    //完整公钥
//    byte[] fullPub = genKey[1];
//
//    //待签名值hash
//    byte[] tbs = provider.hash(new AlgPolicy(AlgPolicy.SHA1), plain);
//    //客户端签名
//    //todo 不明其意,暂未实现
//    byte[] clientSign = ASymUtil.semSign("SHA1withRSA", cs, fullPub, tbs);
//    //服务端签名
//    byte[] serverSign = ASymUtil.semSign("SHA1withRSA", ss, fullPub, tbs);
//
//    //合成签名
////    byte[] fullSign = ASymUtil.combileRSASign(clientSign, serverSign, fullPub);
//    byte[] fullSign = provider.combileRSASign(clientSign, serverSign, fullPub);
//
//    //使用gaia验签
//    boolean b = provider.verifySignHashedData(new AlgPolicy(AlgPolicy.SHA1_RSA), tbs, fullSign,
//        new BjcaKey(BjcaKey.RSA_PUB_KEY, fullPub));
//    System.out.println(b);
////协同签名验签
//    boolean verifySign = ASymUtil.rsaVerifySign(fullPub, tbs, fullSign, "SHA1withRSA");
//    System.out.println(verifySign);
//  }
//
//  // SM2协同签名
//  public static void testSm2SignVerify() throws Exception {
//    byte[] rr = buildPri();
//    //客户端私钥因子
//    byte[] cd = provider.hash(new AlgPolicy(AlgPolicy.SM3), rr);
//    //客户端公钥
//    byte[] cp = provider.generateSM2PublicKeyPoint(cd);
////    byte[] cp = SEMSM2Util.generateSM2PublicKeyPoint(cd);
//
//    //服务端私钥因子,随机?
//    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.SM2), 256);
//    byte[] dsem = bjcaKeyPair.getPrivateKey().getKey();
////    byte[] dsem = SEMSM2Util.generateSEMSM2PrivateKey();
//    //服务端公钥因子
////    byte[] sp = SEMSM2Util.generateSM2PublicKeyPoint(dsem);
//    //完整公钥
//    byte[] pub = provider.generateSM2PublicKey(dsem, cp);
////    byte[] pub = SEMSM2Util.generateSM2PublicKey2(dsem, cp);
//
////    ECPoint fullPoint = SEMSM2Util.pack2Point(pub);
//
//    //待签名数据
//    //TODO hash用公钥参与
////    byte[] hash = SM2Util.SM3ForSignature(plain, fullPoint);
//    SM3Param sm3Param = new SM3Param(pub);
//    AlgPolicy algPolicy = new AlgPolicy(AlgPolicy.SM3, sm3Param);
//    byte[] hash = provider.hash(algPolicy, plain);
//    //服务端k1
//    byte[] sk1 = provider.genRandom(32);
//
//    //服务端签名值
//    byte[] sq = provider.genQ1(sk1);
////    byte[] sq = SEMSM2Util.calckG(sk1);
//
//    //Client Sign2
//    byte[][] cs = provider.serverSign(sq, cd, hash);
////    byte[][] cs = SEMSM2Util.serverSemSign(sq, cd, hash);
//
//    //合并签名
//    byte[] fullSign = SEMSM2Util.clientSemSign(cs[0], cs[1], cs[2], dsem, sk1);
//
////    PublicKey oPub = SEMSM2Util.point2PublicKey(fullPoint);
//    BjcaKey bjcaKeyPub = new BjcaKey(BjcaKey.SM2_PUB_KEY, pub);
//    boolean b = provider
//        .verifySignHashedData(new AlgPolicy(AlgPolicy.SM3_SM2), hash, fullSign, bjcaKeyPub);
//    System.out.println(b);
//
//  }
//
//  public static void test() throws Exception {
//    String deviceInfo = "imei:1234567890,mayao test";
//    byte[] r1 = deviceInfo.getBytes();
//    byte[] r2 = provider.genRandom(16);
//    String pin = "123456";
//    byte[] bwsPin = pin.getBytes();
//
//    byte[] rr = new byte[r1.length + r2.length + bwsPin.length];
//    System.arraycopy(r1, 0, rr, 0, r1.length);
//    System.arraycopy(r2, 0, rr, r1.length, r2.length);
//    System.arraycopy(bwsPin, 0, rr, r1.length + r2.length, bwsPin.length);
//
//    //客户端私钥  Dc
//    byte[] cd = provider.hash(new AlgPolicy(AlgPolicy.SM3), rr);
//    System.out.println("客户端私钥因子=" + EncodeUtil.base64Encode(cd));
//
//    //客户端公钥  Pc=[Dc-1]G
////    byte[] cp = SEMSM2Util.generateSM2PublicKeyPoint(cd);
//    byte[] cp = provider.generateSM2PublicKeyPoint(cd);
//    System.out.println("客户端公钥因子=" + EncodeUtil.base64Encode(cp));
//
//    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.SM2), 256);
//    byte[] dsem = bjcaKeyPair.getPrivateKey().getKey();
//    //服务端私钥因子 todo 由gaia产生私钥替换public static byte[] clientSemSign(byte[] br, byte[] bs2, byte[] bs3, byte[] bd1, byte[] bk1) {
//    //    BigInteger r = EncodeUtil.byteArray2BigInteger(br);
//    //    BigInteger s2 = EncodeUtil.byteArray2BigInteger(bs2);
//    //    BigInteger s3 = EncodeUtil.byteArray2BigInteger(bs3);
//    //    BigInteger d1 = EncodeUtil.byteArray2BigInteger(bd1);
//    //    BigInteger k1 = EncodeUtil.byteArray2BigInteger(bk1);
//    //    BigInteger s = d1.multiply(k1).multiply(s2).add(d1.multiply(s3)).subtract(r).mod(n);
//    //    ASN1EncodableVector aev = new ASN1EncodableVector();
//    //    aev.add(new ASN1Integer(r));
//    //    aev.add(new ASN1Integer(s));
//    //    DERSequence seq = new DERSequence(aev);
//    //
//    //    try {
//    //      return seq.getEncoded();
//    //    } catch (IOException var14) {
//    //      throw new RuntimeException(var14);
//    //    }
//    //  }
////    dsem = SEMSM2Util.generateSEMSM2PrivateKey();
//    System.out.println("SM2服务端私钥=" + EncodeUtil.base64Encode(dsem));
//
//    //服务端公钥因子，一般返回给客户端用于计算完整公钥
////    byte[] sp = SEMSM2Util.generateSM2PublicKeyPoint(dsem);
//
//    //生成完整公钥  P=[Ds-1]Pc-G=（x,y）
//    //私钥为
//    //客户端将[Dc-1]G发给服务端 用户公钥
//    byte[] pub = provider.generateSM2PublicKey(dsem, cp);
////    byte[] pub = SEMSM2Util.generateSM2PublicKey2( dsem , cp);
//
////    ECPoint fullPoint  = SEMSM2Util.pack2Point(pub);
//
//    SM3Param sm3Param = new SM3Param(pub);
//    AlgPolicy algPolicy = new AlgPolicy(AlgPolicy.SM3, sm3Param);
//    //
//    byte[] hash = provider.hash(algPolicy, plain);
//
////    byte[] hash = SM2Util.SM3ForSignature(plain, fullPoint);
//
//    String sHash = EncodeUtil.base64Encode(hash);
//
//    System.out.println("待签名数据=" + sHash);
//
//    //Client Sign1
//    byte[] ck1 = provider.genRandom(32);
//
//    System.out.println("客户端K1=" + EncodeUtil.base64Encode(ck1));
//    byte[] cq = provider.genQ1(ck1);
////    byte[] cq = SEMSM2Util.calckG(ck1);
//
//    System.out.println("SM2客户端签名值 = "+ EncodeUtil.base64Encode(cq));
//
//    //Server Sign2  随机数*G   私钥因子  原文hash(待签名)
//    byte[][] ss = provider.serverSign(cq, dsem, hash);
////    byte[][] ss = SEMSM2Util.serverSemSign(cq, cd, hash);
//
//    System.out.println("SM2服务端签名值 r= "+  EncodeUtil.base64Encode(ss[0]));
//    System.out.println("SM2服务端签名值 s2= "+ EncodeUtil.base64Encode(ss[1]));
//    System.out.println("SM2服务端签名值 s3= "+ EncodeUtil.base64Encode(ss[2]));
//
//    //Client Sign3
////    byte[] fullSign = SEMSM2Util.clientSemSign(ss[0], ss[1], ss[2], cd, ck1);
//    byte[] fullSign = provider.combileSM2SignedData(ss[0], ss[1], ss[2], cd, ck1);
//
//    System.out.println("SM2合并签名值 =" + EncodeUtil.base64Encode(fullSign));
//
//    BjcaKey bjcaKey = new BjcaKey(BjcaKey.SM2_PUB_KEY, pub);
//    boolean b = provider
//        .verifySignHashedData(new AlgPolicy(AlgPolicy.SM3_SM2), hash, fullSign, bjcaKey);
//    System.out.println(b);
//  }
//
//
//
//  private static byte[] buildPri() throws PkiException {
//
//    String pin =  "123456";
//
//    String devInfo = "imei:1234567890,zhenwei test";
//    byte[] r1 = devInfo.getBytes();
//    byte[] random = provider.genRandom(16);
//    byte[] bwsPing = pin.getBytes();
//    byte[] rr = new byte[r1.length+random.length+bwsPing.length];
//    System.arraycopy(r1, 0 , rr , 0, r1.length);
//    System.arraycopy(random, 0, rr, r1.length, random.length);
//    System.arraycopy(bwsPing, 0, rr, r1.length+random.length, bwsPing.length);
//    return rr;
//  }
//
//
//
//}
