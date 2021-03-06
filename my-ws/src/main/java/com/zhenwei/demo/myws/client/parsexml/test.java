package com.zhenwei.demo.myws.client.parsexml;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jdom2.Document;
import org.jdom2.Element;
import org.jdom2.JDOMException;
import org.jdom2.input.SAXBuilder;
import org.xml.sax.InputSource;

/**
 * @ClassName test
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/19 14:16
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

public class test {

  /**
   * 将字符串类型的XML 转化成Docunent文档结构</p>
   *
   * @param parseStrXml 待转换的xml 字符串
   */
  public static Document strXmlToDocument(String parseStrXml) {
    StringReader read = new StringReader(parseStrXml);
    //创建新的输入源SAX 解析器将使用 InputSource 对象来确定如何读取 XML 输入
    InputSource source = new InputSource(read);
    //创建一个新的SAXBuilder
    SAXBuilder sb = new SAXBuilder();     // 新建立构造器
    Document doc = null;
    try {
      doc = sb.build(source);
    } catch (JDOMException e) {
      e.printStackTrace();
    } catch (IOException e) {
      e.printStackTrace();
    }
    return doc;
  }

  /**
   * 根据目标节点名获取值
   *
   * @param doc 文档结构
   * @param finalNodeName 最终节点名
   */
  public static String getValueByElementName(Document doc, String finalNodeName) {
    Element root = doc.getRootElement();
    HashMap<String, Object> map = new HashMap<String, Object>();
    //调用getChildAllText方法。获取目标子节点的值
    Map<String, Object> resultmap = getChildAllText(doc, root, map);
    String result = (String) resultmap.get(finalNodeName);
    return result;
  }

  /**
   * 递归获得子节点的值
   *
   * @param doc 文档结构
   * @param e 节点元素
   * @param resultmap 递归将值压入map中
   */
  public static Map<String, Object> getChildAllText(Document doc, Element e,
      HashMap<String, Object> resultmap) {
    if (e != null) {
      if (e.getChildren() != null)     //如果存在子节点
      {
        List<Element> list = e.getChildren();
        for (Element el : list)      //循环输出
        {
          if (el.getChildren().size() > 0)     //如果子节点还存在子节点，则递归获取
          {
            getChildAllText(doc, el, resultmap);
          } else {
            resultmap.put(el.getName(), el.getTextTrim());   //将叶子节点值压入map
          }
        }
      }
    }
    return resultmap;
  }


  public static String getSoapXml() {
    File file = new File("C:\\Users\\admin\\Desktop\\运营ca\\信步云XML.xml");//信步云XML.xml   信手书SM3.xml

  String s = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
      + "\t<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" >\n"
      + "\n"
      + "\t\t<SOAP-ENV:Header>\n"
      + "\t\t\t<radk:session>\"raSN\"</radk:session>\n"
      + "\t\t\t<radk:msgSig>\n"
      + "\t\t\t\t<alg>sha1</alg>\n"
      + "\t\t\t\t<sigData>\"signResult\"</sigData>\n"
      + "\t\t\t</radk:msgSig>\n"
      + "\t\t</SOAP-ENV:Header>\n"
      + "\n"
      + "\n"
      + "\t<SOAP-ENV:Body>\n"
      + "\t\t<radk:applyOneTimeCert3>\n"
      + "\t\t\t<oneTimeCertReq3>\n"
      + "\t\t\t\t<p10>\"p10\"</p10>\n"
      + "\t\t\t\t<dn>\"CN=\"+ userName + \",\" + rdns  + \",C=CN\";</dn>\n"
      + "\t\t\t\t<notBefore>\"nb\"</notBefore>\n"
      + "\t\t\t\t<notAfter>\"na\"</notAfter>\n"
      + "\t\t\t\t<templName>\"templateID\"</templName>\n"
      + "\t\t\t\t<channel>\"channelID\"</channel> <!-- 渠道号 -->\n"
      + "\t\t\t\t<caid>\"caID\"</caid>\n"
      + "\t\t\t\t<oidlst>\n"
      + "\t\t\t\t<!-- 若uid存在,则填充uid,若不存在,则去掉 item 项-->\n"
      + "\t\t\t\t\t<item>\n"
      + "\t\t\t\t\t\t<oid>\"0.9.2342.19200300.100.1.1\"</oid>\n"
      + "\t\t\t\t\t\t<extValue>\"uid\"</extValue>\n"
      + "\t\t\t\t\t</item>\n"
      + "\t\t\t\t\t<!-- 遍历组装oid和值 替换<%otherextensions%> -->\n"
      + "\t\t\t\t\t<item><oid>\"oid\"</oid><extValue>\"sv\"</extValue></item>\n"
      + "\t\t\t\t\t\n"
      + "\t\t\t\t</oidlist>\n"
      + "\t\t\t</oneTimeCertReq3>\n"
      + "\t\t</radk:applyOneTimeCert3>\n"
      + "\t</SOAP-ENV:Body>\n"
      + "\t</soapenv:Envelope>";

    //发送soap报文
    //解析，获取返回json
    Document document = XMLUtil.strXmlToDocument(s);
    String returnJson = XMLUtil.getValueByElementName(document, "return");
    System.out.print(returnJson);
    return returnJson;
  }


  public static void main(String[] args) {
    getSoapXml();
  }

}
