package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.cloud.ca.pki.common.pkcs.PKCS10;
import cn.org.bjca.gaia.util.encoders.Base64;
import cn.org.bjca.soft.jce.provider.BJCASoftProvider;
import com.sun.org.apache.xerces.internal.jaxp.SAXParserFactoryImpl;
import java.io.ByteArrayInputStream;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.xml.sax.XMLReader;

public class BuildSignData {

  static {
    Security.addProvider(new BJCASoftProvider());
  }

  private static final String UID = "0.9.2342.19200300.100.1.1";

  private static final String xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">\n"
      + "  <soapenv:Header>\n"
      + "    <ns2:msgSig xmlns:ns2=\"urn:radk\" soapenv:mustUnderstand=\"0\">\n"
      + "      <alg>sha1</alg>\n"
      + "      <sigData>JpSs1/ib/FbyMKya1vpp/mZwds+uory8dBuOXOFO9I4OGT/oTVp5y4vMLIZ7JCs+bv/Rs8249TBWQM0Tm7xYN0Tuo4nzZc6XwVTO39yKT8tom4rxJ863Qs5f3Ux9pA0bm3a/I62gm21GNPA2I+FU51ntkHxo04xDoIj/i4eunkg=</sigData>\n"
      + "    </ns2:msgSig>\n"
      + "    <ns2:session xmlns:ns2=\"urn:radk\" soapenv:mustUnderstand=\"0\">2C300000000000003A6B</ns2:session>\n"
      + "  </soapenv:Header>\n"
      + "  <soapenv:Body>\n"
      + "    <ns2:applyOneTimeCert3 xmlns:ns2=\"urn:radk\">\n"
      + "    <oneTimeCertReq3>\n"
      + "        <version>1.0</version>\n"
      + "        <pub-key/> \n"
      + "        <p10>MIIB3jCCAUcCAQAwWzESMBAGA1UEAwwJ5a6B5rOi5biCMQ8wDQYDVQQLDAbnjovmqKExJzAlBgNVBAoMHua1t+WNl+WNk+azsOWItuiNr+aciemZkOWFrOWPuDELMAkGA1UEBhMCQ04wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPQ/kmqw9h+SAtOMLu3526RB+OkhKdDjA+rbBB9JY/VWuUNKRUdh/KHHssdriHx3YQu8W4ikOmnXzT19uUX9MJ1V+ot+xL1LoZpqCgE6IePCWSnPI+iMgXeINFPQ0pqIunROBZOrEieiq/9d/Gv5j+GpKelnVKdAo306KMHS27/NAgMBAAGgQzAeBgQqA49jMRYMFOi/kOiQpUNB5Y2H57qn5rWL6K+VMCEGBCoDj2IxGQwXYmpjYSBpc2lnbmV0IHRlc3QgZ3JvdXAwDQYJKoZIhvcNAQEFBQADgYEAsMlEj3yhxJx5LwvsHqGOonxH0pgA8ODgxibiQZK+qpeXE6auFog4gUHUtojWO5D1G7PvhLYuWF7K1XEXcSgYnBH/2I5bwjtoVFqkA2e31BTMFfmndf9RwWTE3pFqzScQICZcFjfe/tlo4ARTf/axaU5cPIS0qznEJPEPxO3aELU=</p10>\n"
      + "        <dn/>    \n"
      + "        <notBefore>20200509150832</notBefore> \n"
      + "        <notAfter>20210509150832</notAfter> \n"
      + "        <templName>12</templName>\n"
      + "        <channel>102</channel>\n"
      + "        <caid>035</caid>\n"
      + "        <otc-ext/>\n"
      + "        \n"
      + "    </oneTimeCertReq3>\n"
      + "    </ns2:applyOneTimeCert3>\n"
      + "  </soapenv:Body>\n"
      + "</soapenv:Envelope>";

  public static void main(String[] args) {

    Map<String, Object> map = paseXML(xml);
    byte[] bytes = buildSignDataAndRequestVo(map, true);
    System.out.println(Base64.toBase64String(bytes));

  }




  public static Map<String, Object> paseXML(String xmlBody) {

    Map<String, Object> map = new HashMap<>();
    try {
      SAXParserFactory factory = new SAXParserFactoryImpl();
      factory.setValidating(false);
      factory.setNamespaceAware(false);
      SAXParser parser = factory.newSAXParser();
      XMLReader xmlReader = parser.getXMLReader();
      SAXReader saxReader = new SAXReader(xmlReader);
      Document document = saxReader.read(new ByteArrayInputStream(xmlBody.getBytes("UTF-8")));
      Element rootElement = document.getRootElement();//根元素
      //递归获取所有节点,构造map
      forEachElement(rootElement, map);
    } catch (Exception e) {
    }
    return map;
  }

  /**
   * @return void
   * @Date 2019/7/22 9:41
   * @Param [element, map]
   * @Description forEachElement 递归遍历所有xml节点
   **/
  private static void forEachElement(Element element, Map<String, Object> map) {
    List<Element> elements = element.elements();
    for (Element ele : elements) {
      forEachElement(ele, map);
    }

    if (CollectionUtils.isEmpty(elements)) {//递归至叶子节点上一级

      if (!map.containsKey(WSCertRequestParams.OID_LISE)) { //首次填充 oidlist
        map.put(WSCertRequestParams.OID_LISE, new HashMap<>());
      }

      if (element.getName().equalsIgnoreCase(WSCertRequestParams.EXT_KEY)) {//标签名为扩展项oid

        HashMap<String, String> exts = (HashMap<String, String>) map
            .get(WSCertRequestParams.OID_LISE);
        exts.put(element.getStringValue(), null);
      } else if (element.getName()
          .equalsIgnoreCase(WSCertRequestParams.EXT_VALUE)) {//标签名为扩展项extValue

        HashMap<String, String> exts = (HashMap<String, String>) map
            .get(WSCertRequestParams.OID_LISE);
        for (Entry<String, String> entry : exts.entrySet()) {
          if (entry.getValue() == null) {
            exts.put(entry.getKey(), element.getStringValue());
          }
        }
      } else {
        if (!StringUtils.isEmpty(element.getStringValue())) {
          map.put(element.getName(), element.getStringValue());
        }
      }
    }
  }

  /**
   * 数据合并
   *
   * @param source1 数据源1
   * @param source2 数据源2
   */
  private static byte[] mergeByteArray(byte[] source1, byte[] source2) {

    byte[] result = new byte[source1.length + source2.length];

    System.arraycopy(source1, 0, result, 0, source1.length);

    System.arraycopy(source2, 0, result, source1.length, source2.length);

    return result;
  }

  private static byte[] buildSignDataAndRequestVo(Map<String, Object> map,  boolean isXinbuyun) {
    byte[] bytes = {};
    String key = null;
    String value = null;
    try {

      if (map.containsKey(key = WSCertRequestParams.VERSION)) {
        bytes = mergeByteArray(bytes, ((String) map.get(key)).getBytes());
      }
      //校验P10
      if (map.containsKey(key = WSCertRequestParams.P10)) {
        value = (String) map.get(key);
        bytes = mergeByteArray(bytes, Base64.decode(value));
        PKCS10 p10 = new PKCS10(null, value.getBytes());
        if (!map.containsKey(key = WSCertRequestParams.DN)) {
          String subjectDN = p10.getSubject().toString();
          //只有信手书有类似请求:  C=CN,cn=C=CN,cn=C=CN,cn=C=CN,cn=C=CN,cn=c=cn,cn=张玉弟
          if (!isXinbuyun){
            //替换忽略大小写
            subjectDN = subjectDN.replaceAll("(?i)CN=c=cn,", "");
//                        String reOrderDN = reOrderSubjectDN(subjectDN);
          }

        }


      }

      if (map.containsKey(key = WSCertRequestParams.TYPE)) {//公钥算法类型
        bytes = mergeByteArray(bytes, ((String) map.get(key)).getBytes());
      }

      if (map.containsKey(key = WSCertRequestParams.VALUE)) {//裸公钥
        value = (String) map.get(key);
        bytes = mergeByteArray(bytes, Base64.decode(value));
      }

      if (map.containsKey(key = WSCertRequestParams.DN)) {//主题项
        value = (String) map.get(key);
        bytes = mergeByteArray(bytes, value.getBytes());
        //只有信手书有类似请求:  C=CN,cn=C=CN,cn=C=CN,cn=C=CN,cn=C=CN,cn=c=cn,cn=张玉弟
      }

      //有效期
      if (map.containsKey(key = WSCertRequestParams.NOT_BEFORE)) {
        value = (String) map.get(key);
        bytes = mergeByteArray(bytes, value.getBytes());
      }
      if (map.containsKey(key = WSCertRequestParams.NOT_AFTER)) {
        value = (String) map.get(key);
        bytes = mergeByteArray(bytes, value.getBytes());
      }
      //校验策略标识
      if (map.containsKey(key = WSCertRequestParams.TEMPL_NAME)) {
        value = (String) map.get(key);
        bytes = mergeByteArray(bytes, value.getBytes());
      } else {
      }

      if (map.containsKey(key = WSCertRequestParams.CHANNEL)) {
        value = (String) map.get(key);
        bytes = mergeByteArray(bytes, value.getBytes());
      }

      if (map.containsKey(key = WSCertRequestParams.CAID)) {
        bytes = mergeByteArray(bytes, ((String) map.get(key)).getBytes());
      }

      //将session作为RA标识
      if (map.containsKey(key = WSCertRequestParams.SESSION)) {
      }

      //填充自定义扩展项
      if (map.containsKey(WSCertRequestParams.OID_LISE)) {
        Map<String, String> oidList = (Map<String, String>) map.get(WSCertRequestParams.OID_LISE);
        if (!CollectionUtils.isEmpty(oidList)) {
          CertExtension certExtension = null;
          for (Entry<String, String> entry : oidList.entrySet()) {//遍历所有扩展项
            if (StringUtils.isEmpty(entry.getValue())) {
              continue;
            }

            /*
            //部分DN项,通过自定义扩展项传入(UID,T,UNIQUE_IDENTIFIER), 需将其写入DN
            if ((entry.getKey().equalsIgnoreCase(UID) || entry.getKey().equalsIgnoreCase(T) || entry
                .getKey().equalsIgnoreCase(UNIQUE_IDENTIFIER)) && StringUtils
                .isNotEmpty(vo.getSubject())) {//有传入指定扩展项,且DN项不为空
              String dn_key = "";
              //将OID转换为 对应的DN名,X509Name可识别
              if (entry.getKey().equalsIgnoreCase(UID)){
                dn_key="UID";
              }else if (entry.getKey().equalsIgnoreCase(T)){
                dn_key="T";
              }else if(entry.getKey().equalsIgnoreCase(UNIQUE_IDENTIFIER)){
                dn_key="UniqueIdentifier";
              }
              //将指定扩展项,拼接在DN项前
              vo.setSubject(dn_key + "=" + entry.getValue() + "," + vo.getSubject());
              continue;
            }*/

            //部分DN项,通过自定义扩展项传入(UID), 需将其写入DN
            if (entry.getKey().equalsIgnoreCase(UID)) {//有传入指定扩展项,且DN项不为空
              String dn_key = "";
              //将OID转换为 对应的DN名,X509Name可识别
              if (entry.getKey().equalsIgnoreCase(UID)) {
                dn_key = "UID";
              }
              //将指定扩展项,拼接在DN项前
              continue;
            }

            certExtension = new CertExtension();
            certExtension.setOid(entry.getKey());
            certExtension.setOidValue(entry.getValue());
          }
        }
      }
    } catch (Exception e) {
      e.printStackTrace();
    }

    return bytes;
  }

}
