package com.zhenwei.demo.gaiatest.demo;

import java.io.Serializable;

/***************************************************************************
 * <pre></pre>
 * @文件名称: ${FILE_NAME}
 * @包 路   径：  cn.org.bjca.bmca.ca.dto
 * @版权所有：北京数字认证股份有限公司 (C) 2018
 *
 * @类描述:
 * @版本: V1.5
 * @创建时间：2018-4-23 18:05
 *
 *
 *
 * @修改记录：
-----------------------------------------------------------------------------------------------
时间                      |       修改人            |         修改的方法                       |         修改描述                                                                
-----------------------------------------------------------------------------------------------
|                 |                           |                                       
----------------------------------------------------------------------------------------------- 	
 ***************************************************************************/
public class CertExtension implements Serializable {

  private String oid;
  private String oidValue;

  public CertExtension() {
  }

  public String getOid() {
    return oid;
  }

  public void setOid(String oid) {
    this.oid = oid;
  }

  public String getOidValue() {
    return oidValue;
  }

  public void setOidValue(String oidValue) {
    this.oidValue = oidValue;
  }
}
