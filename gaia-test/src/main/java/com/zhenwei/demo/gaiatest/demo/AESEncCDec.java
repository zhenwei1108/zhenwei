package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.param.IVParam;
import cn.org.bjca.gaia.assemb.security.Gaia;
import cn.org.bjca.gaia.util.encoders.Base64;

public class AESEncCDec {

  public static void main(String[] args) throws PkiException {

    String s = "zKtOcSFB0S6Kz7c5P1H4CQ==";
    byte[] decode = Base64.decode(s);

    Gaia gaia = Gaia.getInstance();
    gaia.initProvider(Gaia.BJCA_JE_PROVIDER);
    GaiaProvider provider = gaia.openProvider(Gaia.BJCA_JE_PROVIDER);

    BjcaKey bjcaKey = new BjcaKey(BjcaKey.SM4_KEY, decode);
    IVParam ivParam = new IVParam();
    AlgPolicy algPolicy = new AlgPolicy(AlgPolicy.SM4_CBC_PKCS5PADDING, ivParam);
    byte[] encrypt = provider
        .encrypt(algPolicy, bjcaKey, "123asdf".getBytes());
    System.out.println(Base64.toBase64String(encrypt));

    byte[] decrypt = provider
        .decrypt(algPolicy, bjcaKey, encrypt);
    System.out.println(new String(decrypt));


  }


}
