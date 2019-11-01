package com.zhenwei.demo.myws.client.parsexml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import lombok.Data;

/**
 * @ClassName RootEle
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/19 13:39
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@XmlRootElement(name = "Envelope") // 必须要标明这个元素
@XmlAccessorType(XmlAccessType.FIELD)
@Data
public class RootEle {

  @XmlElement(name="soapenv:Envelope")
  private String Envelope;


  @XmlElement(name="SOAP-ENV:Header")
  private Header header;


}
