package com.zhenwei.test.base64;

import cn.org.bjca.cloud.ca.pki.common.crypto.CryptoToken;
import cn.org.bjca.cloud.ca.pki.common.crypto.CryptoTokenManager;
import cn.org.bjca.cloud.ca.pki.common.crypto.params.CipherParams;
import cn.org.bjca.soft.util.encoders.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * @ClassName EncodeDecode
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/6/21 17:53
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class EncodeDecode {


    public static void main(String[] args) {
        //http请求会将 + 转为空格
//        String cert = "MIIDEDCCArOgAwIBAgISIQLbgWbGh0aVhsnRJg1lR+SrMAwGCCqBHM9VAYN1BQAwOTELMAkGA1UEBgwCQ04xDTALBgNVBAoMBEJKQ0ExDTALBgNVBAsMBEJKQ0ExDDAKBgNVBAMMA0dNSjAeFw0xOTA2MjEwMjM2MTFaFw0yMDA2MjAwMjM2MTFaMIGNMRYwFAYDVQQDDA0xOTIuMTY4LjIwMC4yMQswCQYDVQQGDAJDTjELMAkGA1UECAwCQkoxCzAJBgNVBAcMAkJKMREwDwYDVQQKDAhTWU1NQ1BaWDEOMAwGA1UECwwFR0pNTUoxETAPBgkqhkiG9w0BCQEWAkAuMRYwFAYDVQQtDA0xOTIuMTY4LjIwMC4yMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE8x9p05k11wE9kJkxbtbQa5igvUn4KBmkOf2f1xOHgFkEEPB/BsJ+3myRyOKxZms1h3ZsRGEBFoszvxJ9XMW+iqOCAUIwggE+MAsGA1UdDwQEAwIGwDAJBgNVHRMEAjAAMBAGCGCGSAGG+EQCBARYWFhYMBIGCiqBHIbvMgIBARcEBFhYWFgwbwYDVR0fBGgwZjAtoCugKYYnaHR0cDovLzEyNy4wLjAuMTo5MDkwL2NybC9HTUovR01KXzAuY3JsMDWgM6Axhi9odHRwOi8vMTI3LjAuMC4xOjkwOTAvY3JsL0dNSi9pbmMvR01KX2luY18wLmNybDAdBgNVHQ4EFgQUGyK4ga4H7sfs+gu2WVr8OfYFIuUwHwYDVR0jBBgwFoAUBLVHfxLgvZ/pD296UUgVL0KGRxgwTQYDVR0gBEYwRDBCBgoqgRyG7zIGBAEBMDQwMgYIKwYBBQUHAgEWJmh0dHA6Ly8xMjcuMC4wLjE6OTA5MC9jcHMvR01KL2Nwcy5odG1sMAwGCCqBHM9VAYN1BQADSQAwRgIhAP6RruSHWfKYoNqf9r5VUnOv8U7s7GKurJXG0Lr2JVYMAiEAi0Q98/7NhYkvLZVi2erdhy3wtsnSsESkOS2EYg4cKuY=";
//        byte[] decode = Base64.getDecoder().decode(cert);
//        String s = Base64.getEncoder().encodeToString(decode);
//        System.out.println(s);
        testRSA_EncryptAndDecryptException();

    }


    public static void testRSA_EncryptAndDecryptException(){
        String sm4 = "99NQ70g00kMz2jwrIgN1JQ==";
        String source = "7Z1RhZ6meEKrMFCTvBKvU2zufVZAcGyJahWgyjYt/wc=";
        try {
            CryptoToken token = CryptoTokenManager.getCryptoToken(CryptoToken.BC_SOFT_CRYPT);
            SecretKey secretKeySpec=new SecretKeySpec(cn.org.bjca.soft.util.encoders.Base64.decode(sm4),"SM4");

            CipherParams params = CipherParams.getInstance(CipherParams.SM4);
            params.setAlgorithm(CipherParams.CIPHER_SM4_ECB_NOPADING);
            params.setKey(secretKeySpec);
            byte[] encrypt = token.encrypt(params, Base64.decode(source));
            System.out.println("密文:"+cn.org.bjca.soft.util.encoders.Base64.toBase64String(encrypt));
            byte[] encPri = Base64.decode("93HQDoFKbFfV6DgheasnxtV5pjJaeRxrAcyj/xEsHaQ=");

            byte[] decrypt = token.decrypt(params, encrypt);
            System.out.println("明文:"+Base64.toBase64String(decrypt));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }


    }


}
