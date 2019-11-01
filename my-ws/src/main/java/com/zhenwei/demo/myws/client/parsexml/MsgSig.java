package com.zhenwei.demo.myws.client.parsexml;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import lombok.Data;

/**
 * @ClassName MsgSig
 * @Author zhangzhenwei
 * @Description
 * @Date 2019/7/19 13:46
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 **/

@Data
@XmlAccessorType(XmlAccessType.FIELD)
public class MsgSig {

  private String alg;

  private String sigData;

}
