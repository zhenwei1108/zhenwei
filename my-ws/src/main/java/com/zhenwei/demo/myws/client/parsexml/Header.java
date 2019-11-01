package com.zhenwei.demo.myws.client.parsexml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import lombok.Data;

/**
 * @ClassName header
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/19 13:44
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/
@Data
@XmlAccessorType(XmlAccessType.FIELD)
public class Header {

  private String session;

  private MsgSig msgSig;

}
