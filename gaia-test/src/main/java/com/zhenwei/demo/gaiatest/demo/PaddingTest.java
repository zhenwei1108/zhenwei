package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKeyPair;
import cn.org.bjca.gaia.util.encoders.Base64;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import org.junit.Test;

public class PaddingTest {

  @Test
  public void buildNoPadding() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.RSA), 1024);
    byte[] bytes = provider.genRandom(128);
    byte[] key = bjcaKeyPair.getPrivateKey().getKey();
    byte[] encrypt = provider
        .encrypt(new AlgPolicy(AlgPolicy.RSA_NOPADDING_ENC), bjcaKeyPair.getPublicKey(), bytes);
    byte[] decrypt = provider
        .decrypt(new AlgPolicy(AlgPolicy.RSA_NOPADDING_ENC), bjcaKeyPair.getPrivateKey(), encrypt);
    System.out.println(Base64.toBase64String(decrypt));


  }




}
