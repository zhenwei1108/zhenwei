package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.util.JksUtil;
import cn.org.bjca.gaia.util.encoders.Base64;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import org.junit.Test;

public class JksTest {

  @Test
  public void parseCert(){
    String cert = "MIIFJTCCBA2gAwIBAgIKQAAAAAAAABV0ZTANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJDTjEN\n"
        + "MAsGA1UECgwEQkpDQTEYMBYGA1UECwwPUHVibGljIFRydXN0IENBMRowGAYDVQQDDBFQdWJsaWMg\n"
        + "VHJ1c3QgQ0EtMjAeFw0xMzA0MTExNjAwMDBaFw0yMzA0MTIxNTU5NTlaMFoxCzAJBgNVBAYTAkNO\n"
        + "MRkwFwYDVQQKDBBEU1ZT6K6+5aSH6K+B5LmmMRkwFwYDVQQLDBBEU1ZT6K6+5aSH6K+B5LmmMRUw\n"
        + "EwYDVQQDDAzorr7lpIfor4HkuaYwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAKHIFxJQVK+B\n"
        + "Ix6uIG9CHDzCQUABWIsL9td/+t6ySRDyMZqvl0ZkomS6GFfeqcPjqs0/CDnWcyq7nfK3fmMrc9/M\n"
        + "f76p85eUfGxFCT2DPfvdZh0vuWKrHkoyEIlK34COgdYRPZ2yX82YLS9d5KlxG5JyfW2JKJMvpW79\n"
        + "LD01iCZNAgMBAAGjggJ3MIICczAfBgNVHSMEGDAWgBT7t9RWF1iMI33V+EIB1O13m1fr6TAMBgNV\n"
        + "HQ8EBQMDB/gAMCsGA1UdEAQkMCKADzIwMTMwNDEyMDAwMDAwWoEPMjAyMzA0MTIyMzU5NTlaMAkG\n"
        + "A1UdEwQCMAAwga8GA1UdHwSBpzCBpDBtoGugaaRnMGUxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARC\n"
        + "SkNBMRgwFgYDVQQLDA9QdWJsaWMgVHJ1c3QgQ0ExGjAYBgNVBAMMEVB1YmxpYyBUcnVzdCBDQS0y\n"
        + "MREwDwYDVQQDEwhjYTRjcmwyNTAzoDGgL4YtaHR0cDovL2xkYXAuYmpjYS5vcmcuY24vY3JsL3B0\n"
        + "Y2EvY2E0Y3JsMjUuY3JsMBEGCWCGSAGG+EIBAQQEAwIA/zAqBgtghkgBZQMCATAJCgQbaHR0cDov\n"
        + "L2JqY2Eub3JnLmNuL2JqY2EuY3J0MBQGBSpWCwcJBAtKSjEyMzQ1Njc4OTAXBghghkgBhvhEAgQL\n"
        + "SkoxMjM0NTY3ODkwGwYIKlaGSAGBMAEEDzAxMTAwMDEwMDA0ODkzMDAaBgYqVgsHAQgEEDE1MENA\n"
        + "SkoxMjM0NTY3ODkwgbAGA1UdIASBqDCBpTA1BgkqgRwBxTiBFQEwKDAmBggrBgEFBQcCARYaaHR0\n"
        + "cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwNQYJKoEcAcU4gRUCMCgwJgYIKwYBBQUHAgEWGmh0dHA6\n"
        + "Ly93d3cuYmpjYS5vcmcuY24vY3BzMDUGCSqBHAHFOIEVAzAoMCYGCCsGAQUFBwIBFhpodHRwOi8v\n"
        + "d3d3LmJqY2Eub3JnLmNuL2NwczANBgkqhkiG9w0BAQUFAAOCAQEADjI8yTkJPNNfjPnHtK3EwHUs\n"
        + "1OtvcQWTdCZLlvr6zRiZTScPocvTJfyOX7RaAOhaZ0DzTKjpB/se+X6WUPDmaMaU74x+9KEXK7ly\n"
        + "iidl5niiaV5ahV2ykH890je34Q2ILAn6k5b7nKOEoEeoQ0pzthKrTZnlbdm0MNU59Lnu4ePN2F+c\n"
        + "yfXowrGiVSw3akglFoyeJ9b317gmsEBQ7VSVLJDhkcPyH4ygzwrMIzD9+e2fYJFyjJ4C+EdyV2mt\n"
        + "k+3nOpeGasQtYKxaqiaqpg8eJP86tIKhWBnPzIr7Z4LN96+k8kkUJyTl0pQ+9lXmBF2pja5TrHkQ\n"
        + "Nmdrp7+nW+5Mcg==";
    System.out.println(cert);
  }


  @Test
  public void decJks() throws PkiException {
    String password = "LjI5NDUyODk1Mg==";
    String jks = "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";

    GaiaProvider pro = GaiaUtils.instance();
    JksUtil jksUtil = new JksUtil();
    String s = jksUtil.exportJksCertificate(Base64.decode(jks), password, "05703031");
    System.out.println(s);
    BjcaKey bjcaKey = jksUtil.exportJksKey(Base64.decode(jks), password, password, "3597917");
    System.out.println(Base64.toBase64String(bjcaKey.getKey()));
    AlgPolicy algPolicy = new AlgPolicy(AlgPolicy.SM4_ECB_PKCS5PADDING);

    //待加密数据
//    byte[] data = bjcaKey.getKey();
    byte[] data = Base64.decode("a1fNcuBuATw7AMOkFWrPhEmmQCS1SjE8WeC1P3U0kFc=");

    //加密密钥
    BjcaKey encKey = new BjcaKey(BjcaKey.SM4_KEY, Base64.decode("Zi5a4Ah6WSyYdn+mK24QiA=="));
    byte[] encrypt = pro.encrypt(algPolicy, encKey, data);
    System.out.println(Base64.toBase64String(encrypt));


  }

}
