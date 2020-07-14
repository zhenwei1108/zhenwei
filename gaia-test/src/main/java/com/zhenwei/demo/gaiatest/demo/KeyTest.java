package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.util.encoders.Base64;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;

public class KeyTest {

  public static void main(String[] args) throws PkiException {
    GaiaProvider pro = GaiaUtils.instance();
    BjcaKey bjcaKey = pro.genSymmKey(new AlgPolicy(AlgPolicy.SM4_KEY), 128);
    byte[] key = bjcaKey.getKey();
    String s = Base64.toBase64String(key);
    System.out.println(s);
  }



}
