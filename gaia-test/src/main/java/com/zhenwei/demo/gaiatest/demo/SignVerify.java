package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.cert.BjcaCert;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.param.AlgPolicy;
import cn.org.bjca.gaia.assemb.param.BjcaKey;
import cn.org.bjca.gaia.assemb.param.BjcaKeyPair;
import cn.org.bjca.gaia.assemb.param.SM3Param;
import cn.org.bjca.gaia.assemb.util.CertificateUtil;
import cn.org.bjca.gaia.assemb.util.KeyPairUtil;
import cn.org.bjca.gaia.util.encoders.Base64;
import cn.org.bjca.soft.jce.provider.BJCASoftProvider;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import org.junit.Test;

public class SignVerify {

  static String cert3a6b = "MIIFkTCCBHmgAwIBAgIKLDAAAAAAAAA6azANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTEYMBYGA1UECwwPUHVibGljIFRydXN0IENBMRowGAYDVQQDDBFQdWJsaWMgVHJ1c3QgQ0EtMTAeFw0xNDA0MjAxNjAwMDBaFw0xNjA0MjExNTU5NTlaMFMxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMRIwEAYDVQQLDAnnoJTnqbbpg6gxITAfBgNVBAMMGE1TU1DmtYvor5XnlKjmiLco5rWL6K+VKTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3u+IMFDRaVQMS1zZNLNLfrludvhIqE2lEI0paqqX87QoDlbMxociZfCgpsZPz+VAkHwhQb8BpS49sCMvsqUkbXB0Yk0FduzNunrU2j5/5xkSU3uHFepdk08P50ybGJhDTDd24Wu5Sj/Vaw2le+MHpmMUNg9gwBCY5q7ZR2BmZN8CAwEAAaOCAuowggLmMB8GA1UdIwQYMBaAFKw77K8Mo1AO76+vtE9sO9vRV9KJMB0GA1UdDgQWBBThm8Go1z+1866EkkUTVdh6TiJp+DALBgNVHQ8EBAMCBsAwga0GA1UdHwSBpTCBojBsoGqgaKRmMGQxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMRgwFgYDVQQLDA9QdWJsaWMgVHJ1c3QgQ0ExGjAYBgNVBAMMEVB1YmxpYyBUcnVzdCBDQS0xMRAwDgYDVQQDEwdjYTNjcmwxMDKgMKAuhixodHRwOi8vbGRhcC5iamNhLm9yZy5jbi9jcmwvcHRjYS9jYTNjcmwxLmNybDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIA/zAdBgUqVgsHAQQUU0YxMTAxMDIxOTg4MTExMTMwMTgwHQYFKlYLBwgEFFNGMTEwMTAyMTk4ODExMTEzMDE4MCAGCGCGSAGG+EQCBBRTRjExMDEwMjE5ODgxMTExMzAxODAbBggqVoZIAYEwAQQPOTk5MDAwMTAwMDAzNTI0MCUGCiqBHIbvMgIBBAEEFzFDQFNGMTEwMTAyMTk4ODExMTEzMDE4MCoGC2CGSAFlAwIBMAkKBBtodHRwOi8vYmpjYS5vcmcuY24vYmpjYS5jcnQwDwYFKlYVAQEEBjEwMDAwMDCB5wYDVR0gBIHfMIHcMDUGCSqBHAHFOIEVATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczA1BgkqgRwBxTiBFQIwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwNQYJKoEcAcU4gRUDMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuYmpjYS5vcmcuY24vY3BzMDUGCSqBHAHFOIEVBDAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczANBgkqhkiG9w0BAQUFAAOCAQEAWga6fjJaruXfsEmgwrXcmSJ1N9ofrjfW9JNdsZbnQCKr3NDXhrwwz9gmYUIcD1vZ9rgSm+eNWVIOUJpriQReQURUUMcF3fe4a+xlPRYZKlUmZhXDIgzjuAnVr2f5iMqmQnRMaTN82ogDLzqpKbqL4XdFuxIqF+Win3A/zYHAyXDZXIkJVzuL6siAAGAJqyf+KmO4IxOrowg7SRjxaEHG3HXraRPb5mh5hmsjOCUdmt3OlvjWInk1blIob/rzn74GgZvPz7QxeyvEPeL5332VSNSd9n5/bae9Em3RvSbADyTdXoVME3qWR26qRTY4/GGZ8YFjqwfcug6ET1W4XRbQcg==";
  static String pri = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAN7viDBQ0WlUDEtc2TSzS365bnb4SKhNpRCNKWqql/O0KA5WzMaHImXwoKbGT8/lQJB8IUG/AaUuPbAjL7KlJG1wdGJNBXbszbp61No+f+cZElN7hxXqXZNPD+dMmxiYQ0w3duFruUo/1WsNpXvjB6ZjFDYPYMAQmOau2UdgZmTfAgMBAAECgYAawDNfWNNICEXRZTrLEBinBCk1LWXKjEaaTdYCbqX9IEkOL2wzBlQiV1Vvraw2DhRJQhvbf8f6wim00QQQM7DDF7yfM126xVBlXpPsTtf9pNyIKLzulqr4pLqA/yQe2wt0QORBrXo2qWHC1WM1m/9oxCpsq44WVuWVHJj9YWCngQJBAPJkMKqM+bIkdxCydrcR2T45v7Ia8UpduKAzxePThvaby0FInHwNap4105HYD7oRSPn3BULx7ehT/zJlmHMmlFkCQQDrc7YxSORCXvRHMeukdTMyzLHTJybaBiB8wWFrvPThpOwdv8O1NYE9WFuc8L44bLRG5Ok/MQm5+xKlZpj5Svv3AkA2itr0lbJeJpxwMmhKO4bx3JbJIgznmf1Ad0XxRRjahyYOc6Naur4iCaSo7cBkMx2DudUCQmQxYi1LjtbmGmlJAkEAq1SLCjf5aVaBOOFZkFV8SQXsjDMcMWBt+XoacvSP2TZSXp9xQQZLIiGOoJgKQzLOyBvAoqwDYOMTQWpz/EuVJwJAfok5acMTOmw4ouyr0ezVm5CYgt0a2Cl8y0khFw97y5n/umJcza8b/1IUVQQAxY6X5gWJRNSt8lyv165qe0bwrg==";
  static String data = "MS4wMIIB3jCCAUcCAQAwWzESMBAGA1UEAwwJ5a6B5rOi5biCMQ8wDQYDVQQLDAbnjovmqKExJzAlBgNVBAoMHua1t+WNl+WNk+azsOWItuiNr+aciemZkOWFrOWPuDELMAkGA1UEBhMCQ04wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPQ/kmqw9h+SAtOMLu3526RB+OkhKdDjA+rbBB9JY/VWuUNKRUdh/KHHssdriHx3YQu8W4ikOmnXzT19uUX9MJ1V+ot+xL1LoZpqCgE6IePCWSnPI+iMgXeINFPQ0pqIunROBZOrEieiq/9d/Gv5j+GpKelnVKdAo306KMHS27/NAgMBAAGgQzAeBgQqA49jMRYMFOi/kOiQpUNB5Y2H57qn5rWL6K+VMCEGBCoDj2IxGQwXYmpjYSBpc2lnbmV0IHRlc3QgZ3JvdXAwDQYJKoZIhvcNAQEFBQADgYEAsMlEj3yhxJx5LwvsHqGOonxH0pgA8ODgxibiQZK+qpeXE6auFog4gUHUtojWO5D1G7PvhLYuWF7K1XEXcSgYnBH/2I5bwjtoVFqkA2e31BTMFfmndf9RwWTE3pFqzScQICZcFjfe/tlo4ARTf/axaU5cPIS0qznEJPEPxO3aELUyMDIwMDUwOTE1MDgzMjIwMjEwNTA5MTUwODMyMTIxMDIwMzU=";


  public static void main(String[] args) throws Exception {
  }


  @Test
  public void verifySignData() throws PkiException {
    String signData = "utBQQx2g2HUFtjR2MVXjykLdxvHaZWP9O93B2uxxxtOohv6XbRaELvSCyX4zKPpOQE6rJyXpcQMmma99DNdzpojM4ECxctdjNyms3Vfb+Ajbdy/f5xe7d1Xc3N+9IId4jBLYp7mrz59P2cetZVlogOrF/p0/3uAk/FcJjUxYGgs=";
//    signData = "pAeY44LCk1mgHe3NiwuwIvQP2Qy7Y/gScTGuVY3iktSq4kRUNC0IC6tYVIQpdL9Eei0L+17j+fKofQj0/nibeXvzKl74/IfEwwUVGyQhHzhXB8seO9KAhUy94rr8VzqROA2kyGxkpGLAathZaz/URL2fqnWfNeKsU4rP4XnvnMc=";
    String data = "MIIBajCB2gIBADAzMRIwEAYDVQQDDAlianRlc3QxMTExEDAOBgNVBAoMB3Rlc3QyMjIxCzAJBgNVBAYTAmNuMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDZSpFO6NMMc+v8PxAS4IXlBk7rCRF2wxqI13tqfcA7UeQmcDZukrNcJ9xT4GX6q2g8YYHw+GWBokTG4f/mlwZemRGDChNwjbKBKIcn7rjpsaOyJh1KpBpFMub8nXQKbitD6cnGZotH5Ral+juJZtWx13Dd4RuW9SK/bR4glBj7ZwIDAQABMAcGBSsOAwIdA4GBAAZFIVxE1hy6bo3Ova9xf3F1oC0VGOoc4WrC1yAkWTEU3xTpCMlvIigM67yvPvAZo6P5gjIhkFzUG3LL9AvgPNdPREMtfwh/+JTffrI9uPgUxE6sTIgUFt4MyJVRz0lWTaptYcmfSWGUHmpZr6tl40aOOLj+32uBFAMf7x/OcPpuY249Ymp0ZXN0MTExLE89dGVzdDIyMixjPWNuMjAyMTA3MDIyMTU3MzEyMDIwMDcwMjIxNTczMTEyMTAzNQ==";
    String cert = "MIIFkTCCBHmgAwIBAgIKLDAAAAAAAAA6azANBgkqhkiG9w0BAQUFADBSMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTEYMBYGA1UECwwPUHVibGljIFRydXN0IENBMRowGAYDVQQDDBFQdWJsaWMgVHJ1c3QgQ0EtMTAeFw0xNDA0MjAxNjAwMDBaFw0xNjA0MjExNTU5NTlaMFMxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMRIwEAYDVQQLDAnnoJTnqbbpg6gxITAfBgNVBAMMGE1TU1DmtYvor5XnlKjmiLco5rWL6K+VKTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA3u+IMFDRaVQMS1zZNLNLfrludvhIqE2lEI0paqqX87QoDlbMxociZfCgpsZPz+VAkHwhQb8BpS49sCMvsqUkbXB0Yk0FduzNunrU2j5/5xkSU3uHFepdk08P50ybGJhDTDd24Wu5Sj/Vaw2le+MHpmMUNg9gwBCY5q7ZR2BmZN8CAwEAAaOCAuowggLmMB8GA1UdIwQYMBaAFKw77K8Mo1AO76+vtE9sO9vRV9KJMB0GA1UdDgQWBBThm8Go1z+1866EkkUTVdh6TiJp+DALBgNVHQ8EBAMCBsAwga0GA1UdHwSBpTCBojBsoGqgaKRmMGQxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMRgwFgYDVQQLDA9QdWJsaWMgVHJ1c3QgQ0ExGjAYBgNVBAMMEVB1YmxpYyBUcnVzdCBDQS0xMRAwDgYDVQQDEwdjYTNjcmwxMDKgMKAuhixodHRwOi8vbGRhcC5iamNhLm9yZy5jbi9jcmwvcHRjYS9jYTNjcmwxLmNybDAJBgNVHRMEAjAAMBEGCWCGSAGG+EIBAQQEAwIA/zAdBgUqVgsHAQQUU0YxMTAxMDIxOTg4MTExMTMwMTgwHQYFKlYLBwgEFFNGMTEwMTAyMTk4ODExMTEzMDE4MCAGCGCGSAGG+EQCBBRTRjExMDEwMjE5ODgxMTExMzAxODAbBggqVoZIAYEwAQQPOTk5MDAwMTAwMDAzNTI0MCUGCiqBHIbvMgIBBAEEFzFDQFNGMTEwMTAyMTk4ODExMTEzMDE4MCoGC2CGSAFlAwIBMAkKBBtodHRwOi8vYmpjYS5vcmcuY24vYmpjYS5jcnQwDwYFKlYVAQEEBjEwMDAwMDCB5wYDVR0gBIHfMIHcMDUGCSqBHAHFOIEVATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczA1BgkqgRwBxTiBFQIwKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5iamNhLm9yZy5jbi9jcHMwNQYJKoEcAcU4gRUDMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuYmpjYS5vcmcuY24vY3BzMDUGCSqBHAHFOIEVBDAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczANBgkqhkiG9w0BAQUFAAOCAQEAWga6fjJaruXfsEmgwrXcmSJ1N9ofrjfW9JNdsZbnQCKr3NDXhrwwz9gmYUIcD1vZ9rgSm+eNWVIOUJpriQReQURUUMcF3fe4a+xlPRYZKlUmZhXDIgzjuAnVr2f5iMqmQnRMaTN82ogDLzqpKbqL4XdFuxIqF+Win3A/zYHAyXDZXIkJVzuL6siAAGAJqyf+KmO4IxOrowg7SRjxaEHG3HXraRPb5mh5hmsjOCUdmt3OlvjWInk1blIob/rzn74GgZvPz7QxeyvEPeL5332VSNSd9n5/bae9Em3RvSbADyTdXoVME3qWR26qRTY4/GGZ8YFjqwfcug6ET1W4XRbQcg==";
    GaiaProvider provider = GaiaUtils.instance();
    BjcaCert bjcaCert = new BjcaCert(Base64.decode(cert));
    //Base64.decode(data)   data.getBytes(StandardCharsets.UTF_8)
    boolean b = provider.verifySignData(new AlgPolicy(AlgPolicy.SHA1_RSA),
        Base64.decode(data) ,
        Base64.decode(signData), bjcaCert.getPublicKey());
    boolean b1 = provider.verifySignData(new AlgPolicy(AlgPolicy.SHA1_RSA),
        data.getBytes(StandardCharsets.UTF_8),
        Base64.decode(signData), bjcaCert.getPublicKey());

    System.out.println(b);
    System.out.println(b1);
  }

  @Test
  public void signDate() throws PkiException {

    String data = "44ZNwRWJAJlVtDENyNdIyAaYvqLRE/s7UPtgPNf7YuE=";

    String pri = "zb/uOuxJc8R397ieW39WkrS9yNrPwUWkfMxdReKez/s=";

    BjcaKey bjcaKey = new BjcaKey(BjcaKey.RSA_PRV_KEY, Base64.decode(pri));

    GaiaProvider provider = GaiaUtils.instance();
    byte[] signData = provider
        .signHashedData(new AlgPolicy(AlgPolicy.SHA256_RSA), Base64.decode(data), bjcaKey);

    System.out.println(Base64.toBase64String(signData));

    String cert = "MIIE1TCCBHqgAwIBAgIKGhAAAAAAAAfGozAKBggqgRzPVQGDdTBEMQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTEXMBUGA1UEAwwOQmVpamluZyBTTTIgQ0EwHhcNMjAwNzA5MTYwMDAwWhcNMjAxMDEwMTU1OTU5WjCBqjEbMBkGA1UEKQwSOTExMTAxMDg3MjI2MTk0MTFBMS0wKwYDVQQDDCTljJfkuqzmlbDlrZforqTor4HogqHku73mnInpmZDlhazlj7gxLTArBgNVBAoMJOWMl+S6rOaVsOWtl+iupOivgeiCoeS7veaciemZkOWFrOWPuDEPMA0GA1UEBwwG5YyX5LqsMQ8wDQYDVQQIDAbljJfkuqwxCzAJBgNVBAYMAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEBzZaw1e6ZsqAQGp/FdbDzY2CGMZGyY3uXBPQ7nIckdBdAqFzuPZou2rPvJ036Uzb7wTTCt6UPm0HhCLDeRK6O6OCAuswggLnMB8GA1UdIwQYMBaAFB/mz9SPxSIql0opihXnFsmSNMS2MB0GA1UdDgQWBBSTeacMSaE3E3zMIZ8v5Y8kIbOZqTALBgNVHQ8EBAMCBsAwgZ0GA1UdHwSBlTCBkjBgoF6gXKRaMFgxCzAJBgNVBAYTAkNOMQ0wCwYDVQQKDARCSkNBMQ0wCwYDVQQLDARCSkNBMRcwFQYDVQQDDA5CZWlqaW5nIFNNMiBDQTESMBAGA1UEAxMJY2EyMWNybDI3MC6gLKAqhihodHRwOi8vMTExLjIwNy4xNzcuMTg5L2NybC9jYTIxY3JsMjcuY3JsMCQGCiqBHIbvMgIBAQEEFgwUSko5MTExMDEwODcyMjYxOTQxMUEwYAYIKwYBBQUHAQEEVDBSMCMGCCsGAQUFBzABhhdPQ1NQOi8vb2NzcC5iamNhLm9yZy5jbjArBggrBgEFBQcwAoYfaHR0cDovL2NybC5iamNhLm9yZy5jbi9jYWlzc3VlcjBABgNVHSAEOTA3MDUGCSqBHIbvMgICATAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmJqY2Eub3JnLmNuL2NwczARBglghkgBhvhCAQEEBAMCAP8wIgYKKoEchu8yAgEBCAQUDBI5MTExMDEwODcyMjYxOTQxMUEwJAYKKoEchu8yAgECAgQWDBRKSjkxMTEwMTA4NzIyNjE5NDExQTAfBgoqgRyG7zICAQEOBBEMDzk5ODAwMDEwMDEyMjUxNjAkBgoqgRyG7zICAQEEBBYMFEpKOTExMTAxMDg3MjI2MTk0MTFBMC4GCiqBHIbvMgIBARcEIAweLTFAMjE1MDA5SkowOTExMTAxMDg3MjI2MTk0MTFBMCAGCCqBHNAUBAEEBBQMEjkxMTEwMTA4NzIyNjE5NDExQTAUBgoqgRyG7zICAQEeBAYMBDIyNjcwIgYKKoEchu8yAgEBEQQUDBI5MTExMDEwODcyMjYxOTQxMUEwCgYIKoEcz1UBg3UDSQAwRgIhAN9B2DUdtmeP/6sZJCwZ3y/LTPj+/VRMDPboXD0v5SMXAiEAzz9/21EtDn7HQbXdzs3+XcQmfMjcrQpMY/EqK66dw7Y=";
    BjcaCert bjcaCert = new BjcaCert(Base64.decode(cert));
    BjcaKey publicKey = bjcaCert.getPublicKey();
    System.out.println("公钥:"+Base64.toBase64String(publicKey.getKey()));
    boolean b = provider.verifySignData(new AlgPolicy(AlgPolicy.SHA1_RSA), Base64.decode(data),
        signData, bjcaCert.getPublicKey());
    System.out.println(b);



  }




  public static void verifySignHashedData() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    String signData = "MEUCIBY33CZDjHIu01PYgrsWs83mllImjp6LX/bJalMFIotfAiEA7kbIOqkUfjFmZFo8kKwq4+8rEccbMu5fUtLA+S5PxsE=";
    String hash = "IHz0EFMvkqR97iRc6bEf9x9Xjr12PrO76kTr0EPQGPs=";
    String pubkey = "ICPcNXGFobGcfMeXOeqdzNzUZedOPjxJyo6la6TfjmHVPCa+qX6UGVfqW70kA5+ReeOX4Wnz+oc333v3HDg8ug==";
    BjcaKey bjcaKey = new BjcaKey(BjcaKey.SM2_PUB_KEY, Base64.decode(pubkey));
    boolean b = provider.verifySignHashedData(new AlgPolicy(AlgPolicy.SM3_SM2), Base64.decode(hash),
        Base64.decode(signData), bjcaKey);
    System.out.println(b);
  }


  public static void signVerify() throws Exception {
    BjcaCert cert = CertificateUtil.createCert(Base64.decode(cert3a6b));
    BjcaKey bjcaKey = new BjcaKey(BjcaKey.RSA_PRV_KEY, Base64.decode(pri));
    Signature signature = Signature.getInstance("SHA1WithRSA", new BJCASoftProvider());
    signature.initSign(KeyPairUtil.convertPrivateKey(bjcaKey));
    signature.update(Base64.decode(data));
    byte[] sign = signature.sign();
    System.out.println(Base64.toBase64String(sign));

    signature.initVerify(KeyPairUtil.convertPublicKey(cert.getPublicKey()));
    signature.update(Base64.decode(data));
    boolean verify = signature.verify(sign);
    System.out.println(verify);
  }


  @Test
  public void gaiaSignVerify() throws PkiException {
    GaiaProvider provider = GaiaUtils.instance();
    BjcaKeyPair bjcaKeyPair = provider.genKeyPair(new AlgPolicy(AlgPolicy.RSA), 1024);
   /*
   String pub = "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE9tmKc9gJz9akXCnaqM4A6B6SRWWlP+5Ot+wex0hHH2vHUYtwd6tugZFbBbm0xcTSR+6SYofCEzU/30QFvOX0OQ==";
    String pri = "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQIgbx1DFIuaeAKryJGhf4M0rXqUDgXzPbJMKKpBdWX2VQqhRANCAAT+zbsEOkjCtbQfePI1GDWJUkembyFzmmm0haxY0TmEW+Y6GUcQvVfMlEpNET8x637ogl1ng83sfObvpLEjUAIH";
    String signDataBase = "MEUCIQCpvfLuSACE9TwXDu3yMY1vwUK78JHo1b+u9XL/WH+BjwIgAp2TFY/J/KDsqJOtjzPXb8iG2yMgNTDYW9x/OdsQ6yc=";
    byte[] signData = Base64.decode(signDataBase);
    byte[] decodePub = Base64.decode(pub);
    BjcaKey bjcaKey = KeyPairUtil.subjectPubKeyInfo2Key(decodePub);
    byte[] decodePri = Base64.decode(pri);
    */
    byte[] data = "123asdfasf".getBytes();
    data = Base64.decode("44ZNwRWJAJlVtDENyNdIyAaYvqLRE/s7UPtgPNf7YuE=");
    SM3Param sm3Param = new SM3Param(bjcaKeyPair.getPublicKey().getKey());
    AlgPolicy signAlg = new AlgPolicy(AlgPolicy.SHA256_RSA);

    byte[] signData = provider.signData(signAlg, data, bjcaKeyPair.getPrivateKey());
    boolean b = provider.verifySignData(signAlg, data, signData, bjcaKeyPair.getPublicKey());
    System.out.println(b);

  }





}
