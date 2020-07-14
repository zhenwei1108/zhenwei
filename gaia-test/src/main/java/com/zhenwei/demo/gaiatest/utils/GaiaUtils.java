package com.zhenwei.demo.gaiatest.utils;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.security.Gaia;

public class GaiaUtils {

  public static GaiaProvider instance(){
    GaiaProvider provider = null;
    try {
      Gaia gaia = Gaia.getInstance();
      gaia.initProvider(Gaia.BJCA_JE_PROVIDER);
      provider = gaia.openProvider(Gaia.BJCA_JE_PROVIDER);
    } catch (PkiException e) {
      e.printStackTrace();
    }
    return provider;
  }


}
