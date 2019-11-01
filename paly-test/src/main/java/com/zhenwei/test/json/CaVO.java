package com.zhenwei.test.json;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

/**
 * Created by lyr on 2017-10-18.
 */

public class CaVO implements Serializable {

    private static final long serialVersionUID = -8312284226788019831L;
//    @NotBlank(message="id不能为空或者空白字符")
    private String id;

//    @NotBlank(message="caId不能为空或者空白字符")
    private String caId;
//    @NotBlank(message="caName不能为空或者空白字符")
    private String caName;

    private Byte caStatus;

    private String caSnPrefix;

    private Short keyModulus;

    private String caP10;

    private String keyAlgType;

    private Date caNotBefore;

    private Date caNotAfter;

    private String caType;

    private String caCert;

    private String higherCaId;
//    @NotNull(message="keyIndex不能为空或者空白字符")
//    @Min(value =1)
//    @Max(value=64)
    private Short keyIndex;

    private String crlBase;

    private Date createTime;

    private String sigAlg;

    private String objDn;

    private Map<String,String> map;

    public Map<String, String> getMap() {
        return map;
    }

    public void setMap(Map<String, String> map) {
        this.map = map;
    }

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCaId() {
        return caId;
    }

    public void setCaId(String caId) {
        this.caId = caId;
    }

    public String getCaName() {
        return caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

    public Byte getCaStatus() {
        return caStatus;
    }

    public void setCaStatus(Byte caStatus) {
        this.caStatus = caStatus;
    }

    public String getCaSnPrefix() {
        return caSnPrefix;
    }

    public void setCaSnPrefix(String caSnPrefix) {
        this.caSnPrefix = caSnPrefix;
    }

    public Short getKeyModulus() {
        return keyModulus;
    }

    public void setKeyModulus(Short keyModulus) {
        this.keyModulus = keyModulus;
    }

    public String getCaP10() {
        return caP10;
    }

    public void setCaP10(String caP10) {
        this.caP10 = caP10;
    }

    public String getKeyAlgType() {
        return keyAlgType;
    }

    public void setKeyAlgType(String keyAlgType) {
        this.keyAlgType = keyAlgType;
    }

    public Date getCaNotBefore() {
        return caNotBefore;
    }

    public void setCaNotBefore(Date caNotBefore) {
        this.caNotBefore = caNotBefore;
    }

    public Date getCaNotAfter() {
        return caNotAfter;
    }

    public void setCaNotAfter(Date caNotAfter) {
        this.caNotAfter = caNotAfter;
    }

    public String getCaType() {
        return caType;
    }

    public void setCaType(String caType) {
        this.caType = caType;
    }

    public String getCaCert() {
        return caCert;
    }

    public void setCaCert(String caCert) {
        this.caCert = caCert;
    }

    public String getHigherCaId() {
        return higherCaId;
    }

    public void setHigherCaId(String higherCaId) {
        this.higherCaId = higherCaId;
    }

    public Short getKeyIndex() {
        return keyIndex;
    }

    public void setKeyIndex(Short keyIndex) {
        this.keyIndex = keyIndex;
    }

    public String getCrlBase() {
        return crlBase;
    }

    public void setCrlBase(String crlBase) {
        this.crlBase = crlBase;
    }

    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public String getSigAlg() {
        return sigAlg;
    }

    public void setSigAlg(String sigAlg) {
        this.sigAlg = sigAlg;
    }

    public String getObjDn() {
        return objDn;
    }

    public void setObjDn(String objDn) {
        this.objDn = objDn;
    }
}

