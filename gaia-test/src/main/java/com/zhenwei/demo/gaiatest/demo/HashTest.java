package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.SM3Param;
import cn.org.bjca.gaia.util.encoders.Base64;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import org.junit.Test;

public class HashTest {

  @Test
  public void sm2Hash() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    String data = "1231231asdfasdf";
    String pub = "BKwobAoiSO+iKihYXrHltDfSTmmouKgQCFg5zQ8yNH1f6wPZmSbYvZhJalJpZdRrIqSCpUI1EtPbsOgT7cvL9Ow=";
    System.out.println(Base64.decode(pub).length);
    SM3Param sm3Param = new SM3Param(Base64.decode(pub));
    AlgPolicy hashAlg = new AlgPolicy(AlgPolicy.SM3, sm3Param);
    AlgPolicy algPolicy = new AlgPolicy(AlgPolicy.SHA1);
    byte[] hash = provider.hash(algPolicy, data.getBytes());
    System.out.println(hash.length);


  }



}
