package com.zhenwei.test.json;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * @ClassName ParseObj
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/4/19 14:36
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ParseObj {

    public static void test() {
        //自动忽略大小写
        String json = "{\"CaId\":\"SM2RootCA\",\"caName\":\"SM2 Root CA\",\"caSnPrefix\":\"1\",\"keyIndex\":\"1\",\"keyModulus\":\"256\",\"keyAlgType\":\"SM2\",\"objDn\":\"CN=BMJ SM2 Root CA,O=BMJ SM2 Root CA,C=CN\",\"sigAlg\":\"SM2WithSM2\",\"crlBase\":\"http://192.168.1.1:9090\",\"caNotBefore\":\"2019-01-01T16:00:00:00.000z\",\"caNotAfter\":\"2049-04-18T16:00:00:00.000z\",\"createTime\":\"\"}";
        CaVO caVO1 = JSONObject.parseObject(json, CaVO.class);
        System.out.println(caVO1);
        System.out.println("----------");
        CaVO caVO = JSON.parseObject(json, CaVO.class);
        System.out.println(caVO);


    }


    public static void testFormatJson(){
        SecretKeyVO secretKeyVO = new SecretKeyVO();
        secretKeyVO.setRan("333");
        secretKeyVO.setAlgType("SM4");
        secretKeyVO.setFileId("file");
        secretKeyVO.setFileName("知识文档");
        secretKeyVO.setPlatformId("123");
        Map<String,String> map = new HashMap<>();
        map.put("20032890e54f320df6a0d73e03199936d382","MIIDDDCCArGgAwIBAgISIAMokOVPMg32oNc+AxmZNtOCMAwGCCqBHM9VAYN1BQAwPjELMAkGA1UEBgwCQ04xDTALBgNVBAoMBEJKQ0ExDTALBgNVBAsMBEJKQ0ExETAPBgNVBAMMCExPQ0FMU00yMB4XDTE5MDIyMjA4NDIyNloXDTE5MDkxMDA4NDIyNlowPTELMAkGA1UEBgwCQ04xDTALBgNVBAoMBGJqY2ExDTALBgNVBAsMBGJqY2ExEDAOBgNVBAMMB3lhb3NoZW4wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAARBeF2YYg6QuOSMA6VBhOse9LDyhzAm9OGVjgjMtflRPczpxut2GyQWs1yz0lO2xH1eom1xti3DDgqEjiRSkQDEo4IBjDCCAYgwCwYDVR0PBAQDAgOIMAkGA1UdEwQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwMwga8GA1UdHwSBpzCBpDBMoEqgSIZGaHR0cDovLzE5Mi4xNjguMTM2LjE0OTo3MDcwL2dldC9wa2ktY2EtZGV2L2NybC9MT0NBTFNNMi9MT0NBTFNNMl8wLmNybDBUoFKgUIZOaHR0cDovLzE5Mi4xNjguMTM2LjE0OTo3MDcwL2dldC9wa2ktY2EtZGV2L2NybC9MT0NBTFNNMi9pbmMvTE9DQUxTTTJfaW5jXzAuY3JsMB0GA1UdDgQWBBQSuHntZdDIUqq4+zwuSjVzsioJPzAfBgNVHSMEGDAWgBRrXE2jh2PW0RHkdQ1bCtiSIbZugjBnBgNVHSAEYDBeMFwGCiqBHIbvMgYEAQEwTjBMBggrBgEFBQcCARZAaHR0cDovLzE5Mi4xNjguMTM2LjE0OTo3MDcwL2dldC9wa2ktY2EtZGV2L2Nwcy9MT0NBTFNNMi9jcHMuaHRtbDAMBggqgRzPVQGDdQUAA0cAMEQCIBpLfMjmbDS1pmoYcBFCQoObJVkDMrcQ00Ha/fkQyAlrAiBzkL0u9N0xZXY606sbkUk7M2Vw2oFiPBbcH9ePrTJb0g==");
        secretKeyVO.setUserCert(map);
        String s = JSON.toJSONString(secretKeyVO);
        System.out.println(s);
    }



    public static void main(String[] args) {
//        testFormatJson();

        test();


    }


}
