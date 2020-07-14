package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.util.CollaborateUtil;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import org.junit.Test;

public class TestCollaborate {

  private final byte[] data = "asdf3434asdf".getBytes();


  @Test
  public void sm2CollaborateSign() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    CollaborateUtil util = new CollaborateUtil(provider);
    byte[][] keks = util.genKEK();
    byte[] ekek = keks[0];
    byte[] kekHash = keks[1];

    byte[][] sm2KeyPair = util.genFullSM2Key(ekek, kekHash);
    byte[] encDsem = sm2KeyPair[0];
    byte[] publicKey = sm2KeyPair[1];
    byte[] bytes = util.fullSM2Sign(encDsem, ekek, kekHash, data);
    byte[][] edesmPub = util.confirmGenSM2Key(publicKey, ekek, kekHash);

    byte[][] k1Q = util.sm2UserSign(ekek, kekHash);
    byte[] k1 = k1Q[0];
    byte[] q = k1Q[1];
    byte[][] rs2s3 = util.sm2UserSign(data, encDsem, ekek, kekHash, q);
    byte[] signData = util.sm2UserSign(encDsem, ekek, kekHash, k1, rs2s3[0], rs2s3[1], rs2s3[2]);

    BjcaKey bjcaKey = new BjcaKey(BjcaKey.SM2_PUB_KEY,edesmPub[1]);
    boolean b = provider.verifySignData(new AlgPolicy(AlgPolicy.SM3_SM2), data, signData, bjcaKey);
    System.out.println(b);

  }








}
