package cn.org.bjca.engine;

import org.bjca.pki.module.provider.SoftProvider;
import org.ca.engine.sdk.api.CaService;
import org.ca.engine.sdk.beans.Certification;
import org.ca.engine.sdk.exception.CaServiceException;

/**
 * @ClassName TestCreateCert
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/3/22 15:20
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class TestCreateCert {

    private static final String p10 = "MIH/MIGlAgEAMEMxCzAJBgNVBAYMAkNOMQ4wDAYDVQQKDAVDaGluYTEQMA4GA1UECwwHYmVpamluZzESMBAGA1UEAwwJU00y5rWL6K+VMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE4iVm34VPZWhUrHQ2IM7ryt7y/cw/OIj2JRuUyGCW1zDo1qPSoyW9dk6KmW5bW8xFCAnq5mUaPo8kQ10+pFdUY6AAMAoGCCqBHM9VAYN1A0kAMEYCIQDCA0Wd7FvihjVFb5xPwDconSax3U6cpZIRkXoLFsu+AwIhALh4TSRcMQhd9M//sy7s2OqjQNXMjXIIZVp3hX5yuy8j";
    private static final String caId = "bjca2";
    private static final String templateId = "sm2.xml";

    public static void createCert() {
        try {
            //config配置文件地址
            CaService caService = new CaService("E:\\IDEA-SPACE\\MyTest\\caengine\\src\\main\\config.properties");
            //软密钥地址
            caService.init(new SoftProvider("E:\\IDEA-SPACE\\MyTest\\caengine\\src\\main\\java\\soft"));
            //使用加密机调用
//            caService.init(new SWXAProvider("E:\\IDEA-SPACE\\MyTest\\caengine\\src\\main\\java\\lib\\swsds.ini"));
            Certification certification = caService.certRequest(p10, caId, templateId);
            String signCertData = certification.getSignCertData();
            System.out.println("签名证书:" + signCertData);

        } catch (CaServiceException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        createCert();
    }


}
