package com.zhenwei.demo.gaiatest.tencent;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.security.Gaia;
import cn.org.bjca.gaia.assemb.util.JksUtil;
import cn.org.bjca.gaia.util.encoders.Base64;

public class BuildProperties {

  //加密密钥
  static String dataPriKey = "09391GedS2qbNcmkK2dFuQ==";
  //  密钥原文 待加密数据
 static String key = "QeQiokEtW6bWAGjJh4UT99ImgEVEuMZnb2dMbPbBCAA=";

 //jks文件
  static String jksKey = "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";
  static String password = "jHF8G13zEYJJWQ=="; //JKS密码
  static String keyAlias = "1447723";


  public static void main(String[] args) throws PkiException {
    decPks();
  }


  public static void decPks() throws PkiException {
    Gaia gaia = Gaia.getInstance();
    gaia.initProvider(Gaia.BJCA_JE_PROVIDER);
    GaiaProvider provider = gaia.openProvider(Gaia.BJCA_JE_PROVIDER);

    JksUtil jksUtil = new JksUtil();

    //加密密钥
    BjcaKey encKey = new BjcaKey(BjcaKey.SM4_KEY, Base64.decode(dataPriKey));
    //待加密密钥
    //直接组装密钥
    BjcaKey data;
    data = new BjcaKey(BjcaKey.SM2_PRV_KEY, Base64.decode(key));
    //解析jks 获取密钥
//    data = jksUtil.exportJksKey(Base64.decode(jksKey), password, password, keyAlias);

    byte[] encrypt = provider
        .encrypt(new AlgPolicy(AlgPolicy.SM4_ECB_PKCS5PADDING), encKey, data.getKey());
    System.out.println(Base64.toBase64String(encrypt));

  }




}
