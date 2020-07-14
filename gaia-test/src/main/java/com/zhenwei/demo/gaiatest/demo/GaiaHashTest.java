package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.util.encoders.Base64;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;

public class GaiaHashTest {


  public static void main(String[] args) throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    byte[] hash = provider.hash(new AlgPolicy(AlgPolicy.SM3), "123456".getBytes());
    System.out.println(Base64.toBase64String(hash));
  }

}
