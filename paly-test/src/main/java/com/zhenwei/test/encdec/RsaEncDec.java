package com.zhenwei.test.encdec;

import cn.org.bjca.bmcasdk.cert.CertAppEngine;
import cn.org.bjca.bmcasdk.cert.CertAppEngineDeal;
import cn.org.bjca.bmclient.security.CertificateBasicInfo;
import cn.org.bjca.soft.jce.provider.BJCASoftProvider;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * @ClassName RsaEncDec
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/2 14:53
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class RsaEncDec {

//    private static String cert = "MIIEETCCAvmgAwIBAgISIAHNlP5XSIq5xdqie9KcQs2NMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMRMwEQYDVQQDDApVVHJ1c3QtQ0ExMB4XDTE5MDcwMTA0Mzg1N1oXDTIwMDkyODA0Mzg1N1owODELMAkGA1UEBgwCQ04xKTAnBgNVBAMMIDIxMWEzN2MyOWJiYTExZTk5YTUxMDA1MDU2YThlMzBmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAOoOzq7dsDZayuF6crRz9XbZ1AHkAraigmURv6/UKb3mTSuLIAgyLW5iDxbEUNPuIALCdF4QhhsOH+qXY+obAPnD7FCKn7U0wj/jsYURx6k1NSPe+HkbL9XBsmm2lBWqNxLgCPsaw3i9c0xyMGw9MLd/1tZLWD9M+WiFyBn1yHNZrhXv3mTsxFtn6k2ayquSCBFPFLz6BK6o0JYuitxNlyfJ1/uNDvqx+YewFwnmk5aB2w3BQWK42X+hBCYv+wzcniWa/ar6/6COJTCHHEiDYuDDXdeGc5QrC1wbYvWjKTCLpLS9gy7j1DBgu3L0xcDglI75hKZAevwUvyjPwSWXQIDAQABo4IBGjCCARYwCwYDVR0PBAQDAgSwMAkGA1UdEwQCMAAwgYsGA1UdHwSBgzCBgDA6oDigNoY0aHR0cHM6Ly9jcmwuaXNpZ25ldC5jbi9jcmwvVVRydXN0Q0ExL1VUcnVzdENBMV8wLmNybDBCoECgPoY8aHR0cHM6Ly9jcmwuaXNpZ25ldC5jbi9jcmwvVVRydXN0Q0ExL2luYy9VVHJ1c3RDQTFfaW5jXzAuY3JsMB0GA1UdDgQWBBQ2t1JExBhaBKCZ3Dx9u+t+zw7khjAfBgNVHSMEGDAWgBTmowswUeq/NS97gVHUOriQ4lOPNzAuBghghkgBhvhEAgQiEyAyMTFhMzdjMjliYmExMWU5OWE1MTAwNTA1NmE4ZTMwZjANBgkqhkiG9w0BAQsFAAOCAQEAJVNNkkS19V5Bj0fcN8bhhs606BLMeh7l1ymAHPzAf1GWtQxg40ckLQ2rprAbrg7c69PDW4JzUzqxcStum8pfqQVlUzludWoITUzs/3cr+979eLqJln/A6A/3gIskSEyBsjysGtS16pouqW+0UX6PXB6SCg4eHsnmAoPHiOiXjNoM3Wz6tZNzn+mcmvLNyyKWlA6HFZIm7+WzaGy0w3xSmkK/xFWOv0Rzs6rWbWSt7+A2A4muYIFLj4r7xEs3btu4Uuu2lKECMW0Zl1Kfppv8uj/ILUqenOZp7fPjIBFON2deAGKKYMSAKyvSpp5uDLHG7q0wIA0y323rCSo/GrukgA==";
    private static String sm2_cert = "MIIDDDCCArGgAwIBAgISIAMokOVPMg32oNc+AxmZNtOCMAwGCCqBHM9VAYN1BQAwPjELMAkGA1UEBgwCQ04xDTALBgNVBAoMBEJKQ0ExDTALBgNVBAsMBEJKQ0ExETAPBgNVBAMMCExPQ0FMU00yMB4XDTE5MDIyMjA4NDIyNloXDTE5MDkxMDA4NDIyNlowPTELMAkGA1UEBgwCQ04xDTALBgNVBAoMBGJqY2ExDTALBgNVBAsMBGJqY2ExEDAOBgNVBAMMB3lhb3NoZW4wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARBeF2YYg6QuOSMA6VBhOse9LDyhzAm9OGVjgjMtflRPczpxut2GyQWs1yz0lO2xH1eom1xti3DDgqEjiRSkQDEo4IBjDCCAYgwCwYDVR0PBAQDAgOIMAkGA1UdEwQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwga8GA1UdHwSBpzCBpDBMoEqgSIZGaHR0cDovLzE5Mi4xNjguMTM2LjE0OTo3MDcwL2dldC9wa2ktY2EtZGV2L2NybC9MT0NBTFNNMi9MT0NBTFNNMl8wLmNybDBUoFKgUIZOaHR0cDovLzE5Mi4xNjguMTM2LjE0OTo3MDcwL2dldC9wa2ktY2EtZGV2L2NybC9MT0NBTFNNMi9pbmMvTE9DQUxTTTJfaW5jXzAuY3JsMB0GA1UdDgQWBBQSuHntZdDIUqq4+zwuSjVzsioJPzAfBgNVHSMEGDAWgBRrXE2jh2PW0RHkdQ1bCtiSIbZugjBnBgNVHSAEYDBeMFwGCiqBHIbvMgYEAQEwTjBMBggrBgEFBQcCARZAaHR0cDovLzE5Mi4xNjguMTM2LjE0OTo3MDcwL2dldC9wa2ktY2EtZGV2L2Nwcy9MT0NBTFNNMi9jcHMuaHRtbDAMBggqgRzPVQGDdQUAA0cAMEQCIBpLfMjmbDS1pmoYcBFCQoObJVkDMrcQ00Ha/fkQyAlrAiBzkL0u9N0xZXY606sbkUk7M2Vw2oFiPBbcH9ePrTJb0g==";
    private static String rsa_cert = "MIIEETCCAvmgAwIBAgISIAHNlP5XSIq5xdqie9KcQs2NMA0GCSqGSIb3DQEBCwUAMDExCzAJBgNVBAYMAkNOMQ0wCwYDVQQKDARCSkNBMRMwEQYDVQQDDApVVHJ1c3QtQ0ExMB4XDTE5MDcwMTA0Mzg1N1oXDTIwMDkyODA0Mzg1N1owODELMAkGA1UEBgwCQ04xKTAnBgNVBAMMIDIxMWEzN2MyOWJiYTExZTk5YTUxMDA1MDU2YThlMzBmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAOoOzq7dsDZayuF6crRz9XbZ1AHkAraigmURv6/UKb3mTSuLIAgyLW5iDxbEUNPuIALCdF4QhhsOH+qXY+obAPnD7FCKn7U0wj/jsYURx6k1NSPe+HkbL9XBsmm2lBWqNxLgCPsaw3i9c0xyMGw9MLd/1tZLWD9M+WiFyBn1yHNZrhXv3mTsxFtn6k2ayquSCBFPFLz6BK6o0JYuitxNlyfJ1/uNDvqx+YewFwnmk5aB2w3BQWK42X+hBCYv+wzcniWa/ar6/6COJTCHHEiDYuDDXdeGc5QrC1wbYvWjKTCLpLS9gy7j1DBgu3L0xcDglI75hKZAevwUvyjPwSWXQIDAQABo4IBGjCCARYwCwYDVR0PBAQDAgSwMAkGA1UdEwQCMAAwgYsGA1UdHwSBgzCBgDA6oDigNoY0aHR0cHM6Ly9jcmwuaXNpZ25ldC5jbi9jcmwvVVRydXN0Q0ExL1VUcnVzdENBMV8wLmNybDBCoECgPoY8aHR0cHM6Ly9jcmwuaXNpZ25ldC5jbi9jcmwvVVRydXN0Q0ExL2luYy9VVHJ1c3RDQTFfaW5jXzAuY3JsMB0GA1UdDgQWBBQ2t1JExBhaBKCZ3Dx9u+t+zw7khjAfBgNVHSMEGDAWgBTmowswUeq/NS97gVHUOriQ4lOPNzAuBghghkgBhvhEAgQiEyAyMTFhMzdjMjliYmExMWU5OWE1MTAwNTA1NmE4ZTMwZjANBgkqhkiG9w0BAQsFAAOCAQEAJVNNkkS19V5Bj0fcN8bhhs606BLMeh7l1ymAHPzAf1GWtQxg40ckLQ2rprAbrg7c69PDW4JzUzqxcStum8pfqQVlUzludWoITUzs/3cr+979eLqJln/A6A/3gIskSEyBsjysGtS16pouqW+0UX6PXB6SCg4eHsnmAoPHiOiXjNoM3Wz6tZNzn+mcmvLNyyKWlA6HFZIm7+WzaGy0w3xSmkK/xFWOv0Rzs6rWbWSt7+A2A4muYIFLj4r7xEs3btu4Uuu2lKECMW0Zl1Kfppv8uj/ILUqenOZp7fPjIBFON2deAGKKYMSAKyvSpp5uDLHG7q0wIA0y323rCSo/GrukgA==";
    private static String key = "Tj01LCBEPTMsIG49NSwgcD01YThiMUVIS2hSeVFsM0lVWWZ3dFFZa21RT2tBMmFLMk5wU0QvKzgrYkpSNmZUTjRJdU1MM2ZkVGQrbU40bzFXVDZVZEVYWjdFSThIRHR6dStxUXlWVjZCb3VJeFFDcVorMzVUTkZyb1NsTjU3K0NWWjlMWlM3aEhQNlZ1OThBMXNOcU12YzNmN09aZkZFU242SmtnTnVCS1BvZGdmWXpaWlBibFJVYlBOKzA9LCBTZWc9TnpOTGFGcEJiV3d6WVVsek1HRm9SWEpaUWxkaThmdHksIE11c3Q9MCwgTXVzdE51bT0w";

    private static String alg = "RSA";
    //SM2  RSA


    public static void main(String[] args) {
        String cert = rsa_cert;
        try {
            CertAppEngineDeal engineDeal = CertAppEngine.getInstance();
            CertificateBasicInfo certInfo = engineDeal.getCertInfo(cert);
            PublicKey publicKey = buildKey(Base64.getDecoder().decode(certInfo.getPublicKey()));
            enc(publicKey,key.getBytes());

            /*   CryptoToken cryptoToken = CryptoTokenManager.getCryptoToken(CryptoToken.BC_SOFT_CRYPT);
            CipherParams params =CipherParams.getInstance("RSA/NONE/PKCS1Padding",publicKey);
            byte[] encrypt = cryptoToken.encrypt(params, key.getBytes());
            System.out.println(Base64.getEncoder().encodeToString(encrypt));*/
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void enc( PublicKey publicKey,byte[] source){
        try {
            Cipher cpher = Cipher.getInstance("RSA/NONE/NOPadding");
            cpher.init(1, publicKey);
            byte[] enData = cpher.doFinal(source);
            System.out.println(Base64.getEncoder().encodeToString(enData));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }




    public static PublicKey buildKey(byte[] key){
        try {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance(alg, new BJCASoftProvider());
            PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }





}
