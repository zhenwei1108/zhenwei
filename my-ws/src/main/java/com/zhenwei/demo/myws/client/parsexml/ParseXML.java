package com.zhenwei.demo.myws.client.parsexml;

import java.io.File;
import org.dom4j.Document;
import org.dom4j.DocumentHelper;
import org.dom4j.Element;

/**
 * @ClassName ParseXML
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/19 13:36
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class ParseXML {


  public static void main(String[] args) {

    try {

      File file = new File("C:\\Users\\admin\\Desktop\\运营ca\\信步云XML.xml");//信步云XML.xml   信手书SM3.xml

//      InputStream inputStream = new FileInputStream(file);
//      InputStreamReader reader = new InputStreamReader(inputStream);
      String s = "<?xml version=\\\"1.0\\\" encoding=\\\"utf-8\\\"?>\\n\"\n"
          + "          + \"\\t<SOAP-ENV:Envelope xmlns:SOAP-ENV=\\\"http://schemas.xmlsoap.org/soap/envelope/\\\" >\\n\"\n"
          + "          + \"\\n\"\n"
          + "          + \"\\t\\t<SOAP-ENV:Header>\\n\"\n"
          + "          + \"\\t\\t\\t<radk:session>\\\"raSN\\\"</radk:session>\\n\"\n"
          + "          + \"\\t\\t\\t<radk:msgSig>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<alg>sha1</alg>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<sigData>\\\"signResult\\\"</sigData>\\n\"\n"
          + "          + \"\\t\\t\\t</radk:msgSig>\\n\"\n"
          + "          + \"\\t\\t</SOAP-ENV:Header>\\n\"\n"
          + "          + \"\\n\"\n"
          + "          + \"\\n\"\n"
          + "          + \"\\t<SOAP-ENV:Body>\\n\"\n"
          + "          + \"\\t\\t<radk:applyOneTimeCert3>\\n\"\n"
          + "          + \"\\t\\t\\t<oneTimeCertReq3>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<p10>\\\"p10\\\"</p10>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<dn>\\\"CN=\\\"+ userName + \\\",\\\" + rdns  + \\\",C=CN\\\";</dn>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<notBefore>\\\"nb\\\"</notBefore>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<notAfter>\\\"na\\\"</notAfter>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<templName>\\\"templateID\\\"</templName>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<channel>\\\"channelID\\\"</channel> <!-- 渠道号 -->\\n\"\n"
          + "          + \"\\t\\t\\t\\t<caid>\\\"caID\\\"</caid>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<oidlst>\\n\"\n"
          + "          + \"\\t\\t\\t\\t<!-- 若uid存在,则填充uid,若不存在,则去掉 item 项-->\\n\"\n"
          + "          + \"\\t\\t\\t\\t\\t<item>\\n\"\n"
          + "          + \"\\t\\t\\t\\t\\t\\t<oid>\\\"0.9.2342.19200300.100.1.1\\\"</oid>\\n\"\n"
          + "          + \"\\t\\t\\t\\t\\t\\t<extValue>\\\"uid\\\"</extValue>\\n\"\n"
          + "          + \"\\t\\t\\t\\t\\t</item>\\n\"\n"
          + "          + \"\\t\\t\\t\\t\\t<!-- 遍历组装oid和值 替换<%otherextensions%> -->\\n\"\n"
          + "          + \"\\t\\t\\t\\t\\t<item><oid>\\\"oid\\\"</oid><extValue>\\\"sv\\\"</extValue></item>\\n\"\n"
          + "          + \"\\t\\t\\t\\t\\t\\n\"\n"
          + "          + \"\\t\\t\\t\\t</oidlist>\\n\"\n"
          + "          + \"\\t\\t\\t</oneTimeCertReq3>\\n\"\n"
          + "          + \"\\t\\t</radk:applyOneTimeCert3>\\n\"\n"
          + "          + \"\\t</SOAP-ENV:Body>\\n\"\n"
          + "          + \"\\t</soapenv:Envelope>";
      Document document = DocumentHelper.parseText(s);
      Element rootElement = document.getRootElement();



    } catch (Exception e) {
      e.printStackTrace();
    }
  }


}
