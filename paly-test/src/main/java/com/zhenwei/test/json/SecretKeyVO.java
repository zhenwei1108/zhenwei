package com.zhenwei.test.json;

import java.io.Serializable;
import java.util.Map;

/**
 * @ClassName SecretKeyVO
 * @Description
 * @Author gaowenju
 * @Date 2019/2/20 8:55
 * @Version 1.0
 **/
public class SecretKeyVO implements Serializable {
    private String fileId;//文档id
    private String fileName;//工艺文档
    private Map<String,String> userCert;//<证书序列号,证书>
    private String platformId;//平台标识
    private String ran;//挑战码
    private String algType;//获取密钥的算法, 默认SM4


    public String getAlgType() {
        return algType;
    }

    public void setAlgType(String algType) {
        this.algType = algType;
    }

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getPlatformId() {
        return platformId;
    }

    public void setPlatformId(String platformId) {
        this.platformId = platformId;
    }

    public String getRan() {
        return ran;
    }

    public void setRan(String ran) {
        this.ran = ran;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public Map<String, String> getUserCert() {
        return userCert;
    }

    public void setUserCert(Map<String, String> userCert) {
        this.userCert = userCert;
    }

    @Override
    public String toString() {
        return "SecretKeyVO{" +
                "fileId='" + fileId + '\'' +
                ", fileName='" + fileName + '\'' +
                ", userCert=" + userCert +
                ", platformId='" + platformId + '\'' +
                ", ran='" + ran + '\'' +
                ", algType='" + algType + '\'' +
                '}';
    }
}
