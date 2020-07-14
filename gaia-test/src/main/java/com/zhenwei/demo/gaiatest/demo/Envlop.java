package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.cert.BjcaCert;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.GenKeyParam;
import cn.org.bjca.gaia.assemb.param.IVParam;
import cn.org.bjca.gaia.assemb.param.SymmCipherParam;
import cn.org.bjca.gaia.assemb.util.EnvelopUtil;
import cn.org.bjca.gaia.util.encoders.Base64;
import cn.org.bjca.gaia.util.encoders.Hex;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;

public class Envlop {


  public static void main(String[] args) throws PkiException {
    String cert = "MIICVDCCAfigAwIBAgINK17+/14x9Z/DpMvv6DAMBggqgRzPVQGDdQUAMGExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMSUwIwYDVQQLDBxCSkNBIEFueXdyaXRlIFRydXN0IFNlcnZpY2VzMRwwGgYDVQQDDBNUcnVzdC1TaWduIFNNMiBDQS0xMB4XDTIwMDcwMzA5NTAyMloXDTIxMDcwMzA5NTAyMlowYTELMAkGA1UEBgwCQ04xLTArBgNVBAoMJOW5v+S4nOWuj+Wkp+awkeeIhumbhuWbouaciemZkOWFrOWPuDEPMA0GA1UECwwG5p2O5LmmMRIwEAYDVQQDDAnlm5vlt53nnIEwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATtzGG9DwCOAJ7ELn6zdEOKhqo2Sa4kCgTR3Aiw9t6gI0mAPaSbarQKV/73R1kAaDRNFIQ/4e/7M49lGZXybWSCo4GSMIGPMAsGA1UdDwQEAwIGwDAdBgNVHQ4EFgQUz/1B/GNRx6YWTfpmxR5x8ZP84d0wHwYDVR0jBBgwFoAUzGckQhrD+K0nrNLy5YSBH+nFL64wQAYDVR0gBDkwNzA1BgkqgRyG7zICAgIwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwDAYIKoEcz1UBg3UFAANIADBFAiEAySs+aySWGEg2B0IcH+qg8I46NUo0ZvYfW9DylbvRsvACID1b9IoFcRIs4SqlBYpdbXfHYz8WTk9Ljc2NIt/DQ5PA";
    GaiaProvider provider = GaiaUtils.instance();

    BjcaCert bjcaCert = new BjcaCert(Base64.decode(cert));
    byte[] key = bjcaCert.getPublicKey().getKey();
    String s = Hex.toHexString(key);
    System.out.println(s);
    System.out.println(Base64.toBase64String(key));
    EnvelopUtil envelopUtil = new EnvelopUtil(provider);
    SymmCipherParam symmCipherParam = new SymmCipherParam(new IVParam(), new GenKeyParam(false, -1), 128);
    byte[] bytes = envelopUtil
        .encodeEnvelop(new AlgPolicy(AlgPolicy.SM2), new AlgPolicy(AlgPolicy.SM4_ECB_PKCS5PADDING, symmCipherParam), cert,
            "asdfasfd".getBytes());
    System.out.println(bytes);


  }

}
