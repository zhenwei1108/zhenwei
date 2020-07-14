package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.asn1.ASN1InputStream;
import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.cert.BjcaCert;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.param.BjcaKeyPair;
import cn.org.bjca.gaia.assemb.param.SM3Param;
import cn.org.bjca.gaia.assemb.security.Gaia;
import cn.org.bjca.gaia.assemb.structure.BjcaPkcs7Sign;
import cn.org.bjca.gaia.assemb.util.Pkcs7Util;
import cn.org.bjca.gaia.util.encoders.Base64;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import org.junit.Test;

public class Pkcs7Test {

  private static final String cert = "MIICJDCCAcqgAwIBAgIJIBA0AAAAKZw+MAoGCCqBHM9VAYN1MDExCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMRMwEQYDVQQDDAptc3NwdGVzdGNhMB4XDTIwMDUxNDA1NTY0NloXDTIxMDUxNDA1NTY0NlowaTELMAkGA1UEBgwCQ04xNTAzBgNVBAoMLOa1t+WPo+W4gui1m+enkSjmtYvor5Up6K6h566X5py65pyJ6ZmQ5YWs5Y+4MQ8wDQYDVQQLDAbnmb3noLQxEjAQBgNVBAMMCemrmOmbhOW4gjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABM70XnBkx96onjwgTNGUCcimJWyVWQ/qLZmp9Z0DCNtcA1curkZPXeMLO7j1gAwyVFTW7Qo/yLRMDJzDkOOBLpOjgZIwgY8wHwYDVR0jBBgwFoAUA+nUnNaWHBVNTOyJYFxyZn5w778wHQYDVR0OBBYEFOTjP8Y+aZ1gnOcsRWsiPAbuI2enMAsGA1UdDwQEAwIGwDBABgNVHSAEOTA3MDUGCSqBHIbvMgICAzAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAKBggqgRzPVQGDdQNIADBFAiB7tehVFwXTRHZEElgC+hUGJOCvWiIGp+pAwp6WOc7TmQIhALxxdTC2rdG9yIL9VIY4chDz1GGLUh+/g53G6tYzcPzn";
  private static final String pub = "BM70XnBkx96onjwgTNGUCcimJWyVWQ/qLZmp9Z0DCNtcA1curkZPXeMLO7j1gAwyVFTW7Qo/yLRMDJzDkOOBLpM=";
  private static final String pri = "Cwj/vZr7MI/a4n35mdUVdebrFOpKC/ok3qRyMLB6RiA=";
  private static final String p7 = "MIIFiAYKKoEcz1UGAQQCAqCCBXgwggV0AgEBMQ4wDAYIKoEcz1UBgxEFADAgBgoqgRzPVQYBBAIBoBIEEDEyMzQ1Njc4MTIzNDU2NzigggR4MIIEdDCCBBugAwIBAgIKLRAAAAAAAAVtfTAKBggqgRzPVQGDdTBEMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0EwHhcNMTYwMTEyMTYwMDAwWhcNMjIwMTEzMTU1OTU5WjB8MRIwEAYDVQQpDAkxMjM0NTY3ODExIjAgBgNVBAMMGURzdnPmlbDlrZfnrb7lkI3mtYvor5VzbTIxETAPBgNVBAsMCDFkc3Zzc20yMQ0wCwYDVQQKDARCSkNBMRMwEQYDVQQKDApkc3ZzdGVzdGVyMQswCQYDVQQGDAJDTjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABOKwPDJgWmqSIwdoXVUKwNkVMtJyOUNitq9AFxzFZyqv7x+Iw1zcUWJq9WAGTaVooSgSGcudaqSpf1bcYuBGxlGjggK7MIICtzAfBgNVHSMEGDAWgBQf5s/Uj8UiKpdKKYoV5xbJkjTEtjAdBgNVHQ4EFgQUUf6Xdl6N29PZSMIoBkddSDxVsH0wCwYDVR0PBAQDAgbAMIGbBgNVHR8EgZMwgZAwX6BdoFukWTBXMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0ExETAPBgNVBAMTCGNhMjFjcmwyMC2gK6AphidodHRwOi8vY3JsLmJqY2Eub3JnLmNuL2NybC9jYTIxY3JsMi5jcmwwGwYKKoEchu8yAgEBAQQNDAtKSjEyMzQ1Njc4MTBgBggrBgEFBQcBAQRUMFIwIwYIKwYBBQUHMAGGF09DU1A6Ly9vY3NwLmJqY2Eub3JnLmNuMCsGCCsGAQUFBzAChh9odHRwOi8vY3JsLmJqY2Eub3JnLmNuL2NhaXNzdWVyMGwGA1UdIARlMGMwMAYDVR0gMCkwJwYIKwYBBQUHAgEWGyBodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAvBgNVHSAwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwEQYJYIZIAYb4QgEBBAQDAgD/MBkGCiqBHIbvMgIBAQgECwwJMTIzNDU2NzgxMBsGCiqBHIbvMgIBAgIEDQwLSkoxMjM0NTY3ODEwHwYKKoEchu8yAgEBDgQRDA85OTkwMDAxMDAxMTgwMTMwGwYKKoEchu8yAgEBBAQNDAtKSjEyMzQ1Njc4MTAlBgoqgRyG7zICAQEXBBcMFTEyQDIxNTAwOUpKMDEyMzQ1Njc4MTAXBggqgRzQFAQBBAQLDAkxMjM0NTY3ODEwFAYKKoEchu8yAgEBHgQGDAQxMDUwMAoGCCqBHM9VAYN1A0cAMEQCIDirDrNgmm94vQIGRynhX4Qr27Ok6/z8uDb/Bu6x4+G2AiArrk9MUv0TUdARUPZsQyZRRJEkDBrDzpICtCIEszoFJTGBwDCBvQIBATBSMEQxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMQ0wCwYDVQQLDARCSkNBMRcwFQYDVQQDDA5CZWlqaW5nIFNNMiBDQQIKLRAAAAAAAAVtfTAMBggqgRzPVQGDEQUAMA0GCSqBHM9VAYItAwUABEcwRQIhAKAgfUQ9kaLAe3kd4IGmX+bMbgWs691d8K/Q69DuLWB0AiAcHgjYFfgMjymfHsnkzoolcMVWBP6pp5vUe97rNbSOng==";
  private static BjcaKeyPair sm2BjcaKeyPair;
  static {
    BjcaKey bjcaKeyPub = new BjcaKey(BjcaKey.SM2_PUB_KEY, Base64.decode(pub));
    BjcaKey bjcaKeyPri = new BjcaKey(BjcaKey.SM2_PRV_KEY, Base64.decode(pri));
    sm2BjcaKeyPair = new BjcaKeyPair(bjcaKeyPub, bjcaKeyPri);
  }

  @Test
  public void verifyP7SignedData() throws PkiException, UnsupportedEncodingException {
    String cert = "MIIDKTCCAs6gAwIBAgIKGhAAAAAAAAfFwDAKBggqgRzPVQGDdTBEMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0EwHhcNMjAwNzA4MTYwMDAwWhcNMjAxMDA5MTU1OTU5WjAtMQswCQYDVQQGDAJDTjEeMBwGA1UEAwwV5rWL6K+V5aSa5ZCI5LiA562+5ZCNMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAELoFq01l5g9VckMMuHIzyzDSwbV/YGsG2eTP8+eI/5KVijE6CP51ZuclbtYW/ZNKeXPnQasRcJO69/1Dh1ETgHKOCAb0wggG5MB8GA1UdIwQYMBaAFB/mz9SPxSIql0opihXnFsmSNMS2MB0GA1UdDgQWBBQYiRkw6q4r0atFeBMiOBC0tTDeVTALBgNVHQ8EBAMCBsAwgZ0GA1UdHwSBlTCBkjBgoF6gXKRaMFgxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMQ0wCwYDVQQLDARCSkNBMRcwFQYDVQQDDA5CZWlqaW5nIFNNMiBDQTESMBAGA1UEAxMJY2EyMWNybDI3MC6gLKAqhihodHRwOi8vMTExLjIwNy4xNzcuMTg5L2NybC9jYTIxY3JsMjcuY3JsMCMGCiqBHIbvMgIBAQEEFQwTU0YzNDc5ODIzNzQ5ODI3MzQ4OTAfBghghkgBhvhEAgQTDBEzNDc5ODIzNzQ5ODI3MzQ4OTAfBgoqgRyG7zICAQEOBBEMDzk5ODAwMDEwMDEzMTQyNzAsBgoqgRyG7zICAQEXBB4MHDFAMjE1MDA5U0YwMzQ3OTgyMzc0OTgyNzM0ODkwHwYIKoEc0BQEAQEEEwwRMzQ3OTgyMzc0OTgyNzM0ODkwFAYKKoEchu8yAgEBHgQGDAQxMDUwMAoGCCqBHM9VAYN1A0kAMEYCIQCl5rBEnhaODjbaOcbOjaUXYF9/5AsIbHyAvwLvbRiMBAIhALgFyQKUB4i2JTHUMyRYO6QpPp4UapXrPmxuKOWiU4xH";
    String pub = "BC6BatNZeYPVXJDDLhyM8sw0sG1f2BrBtnkz/PniP+SlYoxOgj+dWbnJW7WFv2TSnlz50GrEXCTuvf9Q4dRE4Bw=";
    BjcaCert bjcaCert = new BjcaCert(Base64.decode(cert));
    BjcaKey publicKey = bjcaCert.getPublicKey();

    String signedData = "MIIEKwYKKoEcz1UGAQQCAqCCBBswggQXAgEBMQ8wDQYJKoEcz1UBgxECBQAwDAYKKoEcz1UGAQQCAaCCAy0wggMpMIICzqADAgECAgoaEAAAAAAAB8XAMAoGCCqBHM9VAYN1MEQxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMQ0wCwYDVQQLDARCSkNBMRcwFQYDVQQDDA5CZWlqaW5nIFNNMiBDQTAeFw0yMDA3MDgxNjAwMDBaFw0yMDEwMDkxNTU5NTlaMC0xCzAJBgNVBAYMAkNOMR4wHAYDVQQDDBXmtYvor5XlpJrlkIjkuIDnrb7lkI0wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAAQugWrTWXmD1VyQwy4cjPLMNLBtX9gawbZ5M/z54j/kpWKMToI/nVm5yVu1hb9k0p5c+dBqxFwk7r3/UOHUROAco4IBvTCCAbkwHwYDVR0jBBgwFoAUH+bP1I/FIiqXSimKFecWyZI0xLYwHQYDVR0OBBYEFBiJGTDqrivRq0V4EyI4ELS1MN5VMAsGA1UdDwQEAwIGwDCBnQYDVR0fBIGVMIGSMGCgXqBcpFowWDELMAkGA1UEBhMCQ04xDTALBgNVBAoMBEJKQ0ExDTALBgNVBAsMBEJKQ0ExFzAVBgNVBAMMDkJlaWppbmcgU00yIENBMRIwEAYDVQQDEwljYTIxY3JsMjcwLqAsoCqGKGh0dHA6Ly8xMTEuMjA3LjE3Ny4xODkvY3JsL2NhMjFjcmwyNy5jcmwwIwYKKoEchu8yAgEBAQQVDBNTRjM0Nzk4MjM3NDk4MjczNDg5MB8GCGCGSAGG+EQCBBMMETM0Nzk4MjM3NDk4MjczNDg5MB8GCiqBHIbvMgIBAQ4EEQwPOTk4MDAwMTAwMTMxNDI3MCwGCiqBHIbvMgIBARcEHgwcMUAyMTUwMDlTRjAzNDc5ODIzNzQ5ODI3MzQ4OTAfBggqgRzQFAQBAQQTDBEzNDc5ODIzNzQ5ODI3MzQ4OTAUBgoqgRyG7zICAQEeBAYMBDEwNTAwCgYIKoEcz1UBg3UDSQAwRgIhAKXmsESeFo4ONto5xs6NpRdgX3/kCwhsfIC/Au9tGIwEAiEAuAXJApQHiLYlMdQzJFg7pCk+nhRqles+bG4o5aJTjEcxgcEwgb4CAQEwUjBEMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0ECChoQAAAAAAAHxcAwDQYJKoEcz1UBgxECBQAwDQYJKoEcz1UBgi0BBQAERzBFAiBbETkcZYZMN0NAvOePF+5JZLqM9pTX0PsXNnQNBCwAcwIhAOCkB+H4vd+Jq2Rb8jTYiTb9ziOW9qJG2f4lJIOniMfH";
    String data = "测试";
    GaiaProvider gaia = GaiaUtils.instance();
    Pkcs7Util pkcs7Util = new Pkcs7Util(gaia);
    byte[] certData = pkcs7Util
        .verifyPkcs7Sign(Base64.decode(signedData), data.getBytes("GBK"));
    System.out.println(Base64.toBase64String(certData));

  }



  public static void main(String[] args) throws PkiException {
    parseP7();
  }


  public static void verifyP7Test() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
//    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.SM2), 256);
    BjcaKey bjcaKeyPub = new BjcaKey(BjcaKey.SM2_PUB_KEY, Base64.decode(pub));
    BjcaKey bjcaKeyPri = new BjcaKey(BjcaKey.SM2_PRV_KEY, Base64.decode(pri));
    BjcaKeyPair bjcaKeyPair = new BjcaKeyPair(bjcaKeyPub, bjcaKeyPri);
    byte[] data = Base64.decode("MTIzNDU2NzgxMjM0NTY3OA==");
    SM3Param sm3Param = new SM3Param(bjcaKeyPub.getKey());
    AlgPolicy signAlg = new AlgPolicy(AlgPolicy.SM3_SM2, sm3Param);
    //p1 签名验签
    byte[] signData = provider.signData(signAlg, data,
        bjcaKeyPri);
    Pkcs7Util pkcs7Util = new Pkcs7Util(provider);
    boolean b = provider.verifySignData(signAlg, data, signData, bjcaKeyPair.getPublicKey());
    System.out.println("pkcs1 验证: "+b);
    //p1转p7 后验签
    byte[] pkcs7Sign = pkcs7Util
        .assembPkcs7Sign(signAlg, signData, cert, data, false);
    System.out.println(pkcs7Sign.length);
    byte[] bytes = pkcs7Util.verifyPkcs7Sign(pkcs7Sign, data);
    System.out.println(Base64.toBase64String(bytes));

  }


  public static void verifyTest() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    Pkcs7Util pkcs7Util = new Pkcs7Util(provider);
    AlgPolicy signAlg = new AlgPolicy(AlgPolicy.SM3_SM2);
    byte[] p1 = Base64.decode("MEUCIQCgIH1EPZGiwHt5HeCBpl/mzG4FrOvdXfCv0OvQ7i1gdAIgHB4I2BX4DI8pnx7J5M6KJXDFVgT+qaeb1Hve6zW0jp4=");
    byte[] pkcs7Sign = pkcs7Util
        .assembPkcs7Sign(signAlg, p1, cert, "1234567812345678".getBytes(), false);
    System.out.println(Base64.toBase64String(pkcs7Sign));

  }


  public static void p1ToP7() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    Pkcs7Util pkcs7Util = new Pkcs7Util(provider);
    byte[] data = "123asdfasdf".getBytes();
    AlgPolicy hashAlg = new AlgPolicy(AlgPolicy.SM3);
    AlgPolicy signAlg = new AlgPolicy(AlgPolicy.SM3_SM2);
    byte[] hash = provider.hash(hashAlg, data);
    byte[] signData = provider.signHashedData(signAlg, hash, sm2BjcaKeyPair.getPrivateKey());
    byte[] pkcs7SignDigest = pkcs7Util.assembPkcs7SignDigest(signAlg, cert, signData, data, false);
    byte[] bytes = pkcs7Util.verifyPkcs7SignDigest(pkcs7SignDigest, hash);
    System.out.println(bytes == null?"空":Base64.toBase64String(bytes));
  }

  public static void test() throws PkiException {
    String pri = "a1fNcuBuATw7AMOkFWrPhEmmQCS1SjE8WeC1P3U0kFc=";
    String pub = "BOKwPDJgWmqSIwdoXVUKwNkVMtJyOUNitq9AFxzFZyqv7x+Iw1zcUWJq9WAGTaVooSgSGcudaqSpf1bcYuBGxlE=";
    String cert = "MIIEdDCCBBugAwIBAgIKLRAAAAAAAAVtfTAKBggqgRzPVQGDdTBEMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0EwHhcNMTYwMTEyMTYwMDAwWhcNMjIwMTEzMTU1OTU5WjB8MRIwEAYDVQQpDAkxMjM0NTY3ODExIjAgBgNVBAMMGURzdnPmlbDlrZfnrb7lkI3mtYvor5VzbTIxETAPBgNVBAsMCDFkc3Zzc20yMQ0wCwYDVQQKDARCSkNBMRMwEQYDVQQKDApkc3ZzdGVzdGVyMQswCQYDVQQGDAJDTjBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABOKwPDJgWmqSIwdoXVUKwNkVMtJyOUNitq9AFxzFZyqv7x+Iw1zcUWJq9WAGTaVooSgSGcudaqSpf1bcYuBGxlGjggK7MIICtzAfBgNVHSMEGDAWgBQf5s/Uj8UiKpdKKYoV5xbJkjTEtjAdBgNVHQ4EFgQUUf6Xdl6N29PZSMIoBkddSDxVsH0wCwYDVR0PBAQDAgbAMIGbBgNVHR8EgZMwgZAwX6BdoFukWTBXMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0ExETAPBgNVBAMTCGNhMjFjcmwyMC2gK6AphidodHRwOi8vY3JsLmJqY2Eub3JnLmNuL2NybC9jYTIxY3JsMi5jcmwwGwYKKoEchu8yAgEBAQQNDAtKSjEyMzQ1Njc4MTBgBggrBgEFBQcBAQRUMFIwIwYIKwYBBQUHMAGGF09DU1A6Ly9vY3NwLmJqY2Eub3JnLmNuMCsGCCsGAQUFBzAChh9odHRwOi8vY3JsLmJqY2Eub3JnLmNuL2NhaXNzdWVyMGwGA1UdIARlMGMwMAYDVR0gMCkwJwYIKwYBBQUHAgEWGyBodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczAvBgNVHSAwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwEQYJYIZIAYb4QgEBBAQDAgD/MBkGCiqBHIbvMgIBAQgECwwJMTIzNDU2NzgxMBsGCiqBHIbvMgIBAgIEDQwLSkoxMjM0NTY3ODEwHwYKKoEchu8yAgEBDgQRDA85OTkwMDAxMDAxMTgwMTMwGwYKKoEchu8yAgEBBAQNDAtKSjEyMzQ1Njc4MTAlBgoqgRyG7zICAQEXBBcMFTEyQDIxNTAwOUpKMDEyMzQ1Njc4MTAXBggqgRzQFAQBBAQLDAkxMjM0NTY3ODEwFAYKKoEchu8yAgEBHgQGDAQxMDUwMAoGCCqBHM9VAYN1A0cAMEQCIDirDrNgmm94vQIGRynhX4Qr27Ok6/z8uDb/Bu6x4+G2AiArrk9MUv0TUdARUPZsQyZRRJEkDBrDzpICtCIEszoFJQ==";
    BjcaKey bjcaKeyPub = new BjcaKey(BjcaKey.SM2_PUB_KEY, Base64.decode(pub));
    BjcaKey bjcaKeyPri = new BjcaKey(BjcaKey.SM2_PRV_KEY, Base64.decode(pri));
    byte[] data = Base64.decode("MTIzNDU2NzgxMjM0NTY3OA==");
    Gaia gaia = Gaia.getInstance();
    gaia.initProvider(Gaia.BJCA_SO_PROVIDER);
    GaiaProvider provider = gaia.openProvider(Gaia.BJCA_SO_PROVIDER);
    SM3Param sm3Param = new SM3Param(Base64.decode(pub));
    byte[] hash = provider.hash(new AlgPolicy(AlgPolicy.SM3, sm3Param), data);
    System.out.println(Base64.toBase64String(hash));
    //POnmNA0LzgA34TjwZ8ofIGF6dp4au1KinEVAxUGexPQ=
    AlgPolicy signAlg = new AlgPolicy(AlgPolicy.SM3_SM2, sm3Param);
    byte[] p1Sign = provider.signData(signAlg, data, bjcaKeyPri);
    System.out.println(Base64.toBase64String(p1Sign));
    boolean b = provider.verifySignData(signAlg, data, p1Sign, bjcaKeyPub);
    System.out.println(b);
    Pkcs7Util pkcs7Util = new Pkcs7Util(provider);
    byte[] pkcs7Sign = pkcs7Util.assembPkcs7Sign(signAlg, p1Sign, cert, data, true);
    byte[] getCert = pkcs7Util.verifyPkcs7Sign(pkcs7Sign, data);
    System.out.println(Base64.toBase64String(getCert));

  }


  public static void parseP7() throws PkiException {
    String p7 = "MIIFRgYJKoZIhvcNAQcCoIIFNzCCBTMCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCA7cwggOzMIICm6ADAgECAgwiABAIRCUSAGEBiYswDQYJKoZIhvcNAQELBQAwQjELMAkGA1UEBgwCQ04xDTALBgNVBAoMBEJKQ0ExDTALBgNVBAsMBEJKQ0ExFTATBgNVBAMMDExPQ0FMUlNBMjA0ODAeFw0yMDA2MTAxMDU3NTFaFw0yMDA2MTExMDU3NTFaMB4xDzANBgNVBAMMBuWImOm7hDELMAkGA1UEBgwCY24wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN1SyrkfsXpuROhq+cVzEg43RHJkJHW2mswxILxlQYqZYUgNs5DtoI3cdQ2+YamQOyonQg+JUpVUZVxACTl5glewn25138ksM7tZOW0xkdAx/h5CnjXMp2iX6aokhlPUumgMMORsd3pQOm7iNzobn9sS/QrsQrKpdcFP7Vgml0ZPAgMBAAGjggFPMIIBSzALBgNVHQ8EBAMCB4AwCQYDVR0TBAIwADCBlwYDVR0fBIGPMIGMMECgPqA8hjpodHRwczovL2NybC5pc2lnbmV0LmNuL2NybC9MT0NBTFJTQTIwNDgvTE9DQUxSU0EyMDQ4XzAuY3JsMEigRqBEhkJodHRwczovL2NybC5pc2lnbmV0LmNuL2NybC9MT0NBTFJTQTIwNDgvaW5jL0xPQ0FMUlNBMjA0OF9pbmNfMC5jcmwwHQYDVR0OBBYEFPQ2sAbdQqyuH5ZB6MuGDkflQ8HFMB8GA1UdIwQYMBaAFMSlAzWM9nr7S2cgzLrRKZEBI/iVMFcGA1UdIARQME4wTAYKKoEchu8yBgQBATA+MDwGCCsGAQUFBwIBFjBodHRwczovL2NybC5pc2lnbmV0LmNuL2Nwcy9MT0NBTFJTQTIwNDgvY3BzLmh0bWwwDQYJKoZIhvcNAQELBQADggEBAASz4ZFsBTcx70PGmzlVOg8aZY4097H5PfTsOHlQyRmSc5cRw3rCgqxbEqXhdEnFgOYruvMLoB+MxMyFt/TVLb8WivqMZltPIZ3G6TQMMklJizr004fv6p++Dfy3/dVYzFQAVIOFZ+bW6v7AqLIdC591VH8htWSdGEPYkq4yCOPq8rsZIRCOqIB6gdWHGDTDJ4DUmZjyngZvQQxr4Bp1lHKjaHJ8Am+PREJRurfsA1dbs6eWdyxtzpico4JvQGtvu5s8zWRcMDIZ65MlOdc+QoC2YNg/RJoN1vqnK2k9m5/WdRWxOgrJiBclWIWfdm1U2WzH55CKYmMYcHvmTKJJdHUxggFXMIIBUwIBATBSMEIxCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMQ0wCwYDVQQLDARCSkNBMRUwEwYDVQQDDAxMT0NBTFJTQTIwNDgCDCIAEAhEJRIAYQGJizAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwNjExMDMzNTQxWjAjBgkqhkiG9w0BCQQxFgQUQEEeFgEn7yQhGsAY8kI+p9O1HEgwDQYJKoZIhvcNAQEBBQAEgYB5foRkAkR6LKv43N6BTqoqQWlDZkV87K4EqJtHpnCxvCEUBfg7cICGjOg0RTJsz3i9NNI7Ll7XEcfXSddUHxFXk3W2jU0+or2KHpG6aD6F21pvaYtkb4sgOH7yddZoOAJXAoIhGuZOLUr/zn15A39aEPykwGDc+AGmv1geWGS3tg==";
    GaiaProvider provider = GaiaUtils.instance();
    Pkcs7Util pkcs7Util = new Pkcs7Util(provider);
    BjcaPkcs7Sign bjcaPkcs7Sign = pkcs7Util.parseP7Structure(Base64.decode(p7));
    System.out.println(bjcaPkcs7Sign);

  }



  public void getP7(){
    String p7 = "MIIFRgYJKoZIhvcNAQcCoIIFNzCCBTMCAQExCzAJBgUrDgMCGgUAMAsGCSqGSIb3DQEHAaCCA7cwggOzMIICm6ADAgECAgwiABAIRCUSAGEBiYswDQYJKoZIhvcNAQELBQAwQjELMAkGA1UEBgwCQ04xDTALBgNVBAoMBEJKQ0ExDTALBgNVBAsMBEJKQ0ExFTATBgNVBAMMDExPQ0FMUlNBMjA0ODAeFw0yMDA2MTAxMDU3NTFaFw0yMDA2MTExMDU3NTFaMB4xDzANBgNVBAMMBuWImOm7hDELMAkGA1UEBgwCY24wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAN1SyrkfsXpuROhq+cVzEg43RHJkJHW2mswxILxlQYqZYUgNs5DtoI3cdQ2+YamQOyonQg+JUpVUZVxACTl5glewn25138ksM7tZOW0xkdAx/h5CnjXMp2iX6aokhlPUumgMMORsd3pQOm7iNzobn9sS/QrsQrKpdcFP7Vgml0ZPAgMBAAGjggFPMIIBSzALBgNVHQ8EBAMCB4AwCQYDVR0TBAIwADCBlwYDVR0fBIGPMIGMMECgPqA8hjpodHRwczovL2NybC5pc2lnbmV0LmNuL2NybC9MT0NBTFJTQTIwNDgvTE9DQUxSU0EyMDQ4XzAuY3JsMEigRqBEhkJodHRwczovL2NybC5pc2lnbmV0LmNuL2NybC9MT0NBTFJTQTIwNDgvaW5jL0xPQ0FMUlNBMjA0OF9pbmNfMC5jcmwwHQYDVR0OBBYEFPQ2sAbdQqyuH5ZB6MuGDkflQ8HFMB8GA1UdIwQYMBaAFMSlAzWM9nr7S2cgzLrRKZEBI/iVMFcGA1UdIARQME4wTAYKKoEchu8yBgQBATA+MDwGCCsGAQUFBwIBFjBodHRwczovL2NybC5pc2lnbmV0LmNuL2Nwcy9MT0NBTFJTQTIwNDgvY3BzLmh0bWwwDQYJKoZIhvcNAQELBQADggEBAASz4ZFsBTcx70PGmzlVOg8aZY4097H5PfTsOHlQyRmSc5cRw3rCgqxbEqXhdEnFgOYruvMLoB+MxMyFt/TVLb8WivqMZltPIZ3G6TQMMklJizr004fv6p++Dfy3/dVYzFQAVIOFZ+bW6v7AqLIdC591VH8htWSdGEPYkq4yCOPq8rsZIRCOqIB6gdWHGDTDJ4DUmZjyngZvQQxr4Bp1lHKjaHJ8Am+PREJRurfsA1dbs6eWdyxtzpico4JvQGtvu5s8zWRcMDIZ65MlOdc+QoC2YNg/RJoN1vqnK2k9m5/WdRWxOgrJiBclWIWfdm1U2WzH55CKYmMYcHvmTKJJdHUxggFXMIIBUwIBATBSMEIxCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMQ0wCwYDVQQLDARCSkNBMRUwEwYDVQQDDAxMT0NBTFJTQTIwNDgCDCIAEAhEJRIAYQGJizAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjAwNjExMDMzNTQxWjAjBgkqhkiG9w0BCQQxFgQUQEEeFgEn7yQhGsAY8kI+p9O1HEgwDQYJKoZIhvcNAQEBBQAEgYB5foRkAkR6LKv43N6BTqoqQWlDZkV87K4EqJtHpnCxvCEUBfg7cICGjOg0RTJsz3i9NNI7Ll7XEcfXSddUHxFXk3W2jU0+or2KHpG6aD6F21pvaYtkb4sgOH7yddZoOAJXAoIhGuZOLUr/zn15A39aEPykwGDc+AGmv1geWGS3tg==";
    byte[] envelop = Base64.decode(p7);
    ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(envelop));


  }



}
