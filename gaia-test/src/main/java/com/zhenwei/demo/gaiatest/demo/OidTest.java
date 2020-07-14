package com.zhenwei.demo.gaiatest.demo;

import cn.org.bjca.gaia.assemb.base.GaiaProvider;
import cn.org.bjca.gaia.assemb.cert.BjcaCert;
import cn.org.bjca.gaia.assemb.exception.PkiException;
import cn.org.bjca.gaia.assemb.extension.SelfDefExtension;
import cn.org.bjca.gaia.assemb.util.CertificateUtil;
import cn.org.bjca.gaia.util.encoders.Base64;
import com.zhenwei.demo.gaiatest.utils.GaiaUtils;
import org.junit.Test;

public class OidTest {

  @Test
  public void getOidValue() throws PkiException {
    String certString = "MIITgjCCEuugAwIBAgINK17gq44mslFiSbK2pjANBgkqhkiG9w0BAQUFADA6MQswCQYDVQQGEwJDTjENMAsGA1UECgwEQkpDQTENMAsGA1UECwwEQkpDQTENMAsGA1UEAwwEWFhYWDAeFw0yMDA2MTAwOTQ0NDZaFw0yMTA2MTAwOTQ0NDZaMIGNMQswCQYDVQQGDAJDTjE7MDkGA1UECgwy6L+e5LqR5riv5biC6I+y5LyYKOa1i+ivlSnmioDmnK/mnInpmZDotKPku7vlhazlj7gxLTArBgNVBAsMJOa1meaxn+WYieWMlumbhuWbouiCoeS7veaciemZkOWFrOWPuDESMBAGA1UEAwwJ546L5Lyg54WmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAriWyG9vChxaS+kbkS34F7tDUmuYaSMPOE2Z1UMBS8q5XYsotT54p3MKUsN6yNImvjHDYfnM4eoTEHNPnwZWGG4nq5nZYaYT8KpYufFoDhwjsqkluZaoOW73b+De6/32tnTeAIuH615FojE1JeCnzLf8/4EvwIiSUm/nTXoiF0gRvUmBBi0l4YzU/TH2EgsgxdI+xkHHAqGupCazeovYXMdMsQAeJhbUlgM3oaFMOjaoS+YRLyYuiQYBWE571mI2A5bhvvYsu2rB7p+WyQYGzrWZM41v51yi8frBr2VC4s2/17nQTfE/DUlWSimxucJtw28eNQgJhh/tlOOMhwsmGJwIDAQABo4IQsjCCEK4wCwYDVR0PBAQDAgbAMB0GA1UdDgQWBBRoNj/aJHVqH0+xtgrwweR8P7YMDTAfBgNVHSMEGDAWgBQXtf/sB+ejPj+QA5QbMf6V4rYNuzA5BgNVHSAEMjAwMC4GAikBMCgwJgYIKwYBBQUHAgEWGmh0dHA6Ly8xMjcuMC4wLjE6OTA5MC9wYXRoMB4GCiqBHIbvMgIBCQEEEGRHVnpkQ0J2ZEdOZlpYaDAwQAYLYIZIAWUDAgEwCQoEMWh0dHBzOi8vYXBpLXNpdC5pc2lnbmV0LmNuOjgwODIvY2VydC92Mi9hcHBseWNlcnQwOQYDVQQsBDJUNUdEQzBjN3c2bmAxNlZxSVU1TnF+S0hndUd2eE1DY2B4ZVdQc1c4MWB2OU5IeUY0VDA5BgNVBCkEMlNrdWBCdllmMDUyNVlEeWhmOFBUbjRkR3N+UDBHWEtNM1hhUWBvNW41bFVNMTRofjRVMD4GCCpWhkgBgTABBDIyMW5+NWgyN0N5cUNzNWdPMHRob0w3djFnMmhGUUc0Z25XVzF1UkY3R1A5Z3J+cVNDNDCBmAYIKlaGSAGBMAIEgYtXdzBLZXlKdmFXUWlPaUl4TGpJdU9EWXVNVEV1Tnk0eExqZ2lMQ0p2YVdSV1lXeDFaU0k2SW1WNGRGWmhiSFZsTVNKOURRcDdJbTlwWkNJNklqRXVNaTQ0Tmk0eE1TNDNMakV1T1NJc0ltOXBaRlpoYkhWbElqb2laWGgwVm1Gc2RXVXlJbjBOQ2wwMDwGBipWCwcBAQQyNk1lRXYyYll0NGg0M09+VFJuZ3pZeGhnOGNiOXdVMXA3YnBuelRRdWVxNkdrbG9NazQwPgYIKlYLB2QBAQIEMmZ5ZjNnR2toNHFHT0V+S3NJQWJjU2hMaTU5elp1fmJTbWMwR0VPckhxaGFJYGJvUVFIMDsGBSpWFQEBBDJJdXNSQTNmWjZXYTRtMnlhOFZFN0s3fjMzeXRXfnFCUFBOZ01yOTlNblRSWTc5bE5uejA8BgYqVgsHAQIEMjRxOGZifldVNXgySVBEVFJjMXREflk3Q3NBNk43MTNWblkxVTJMRjZLNXFXMzU0UmcxMD4GCCpWCwdkAQEBBDJnVTF3OU5CUHZ2eDd+S1UxMDNuemlUVkxDc3gyZzhrcUNoUlJEQ25zMm4xWTg2c0d2ZzCCC+UGJypWCwcBAgEDBAUGBwgCVgsHAQIBAwQFBgcIAlYLBwECAQMEBQYHCASCC7gzaXZGZTFndmtBczI2SHg1Tm9YYDRPd01nR2BDMGluSXo1ZGhCNzdSdUF+azVUWjE3QX5FcX5uaFlSMW1DWjNDMFgxOHE5NW9MdVR4NXVsM0dsOFFtM2AwRjg0a0Q3MUlEUUs0QU5wcDJ1b1VJN3dsczMycmc0YG5ZM2EwMkRBMG5UNVpaMmM5NTIxelV1OUcya2xsQTZMflI1aGFVeWQ0djY5WTY5VW04ODhpUVNZbzFzc0VHUDZZN1QwN1REQVcyTm9vcFloTDRQaGtnNDl4VnNzUkRTOH5vUjgzeGF3TDlZc0VmZzRgM3hnfnN0bVgzZDBCTDI1Ykt5OFB5ZWlxcTZRaU5lY1V5WFg3Y003R2ByT3NRNnI5MXQyR3V2MUdnS0g5VVVzUVhsNURQS2ZrT3ZvVGI5TjdNT0UzOTZQODRgV2YwUmlvYTVEdTlINnJgYmd6bDhkZVNEbX52R0g0Y2xiUzJMNWFDU2FJZGdBRTl6enBMRWE3SGdRRmtlcVJHfjlmYzF3M2RNfjEwYzk4TjNaZzcwczhNR3phRDR2ZzV4Z1N5SGdadlIxb2Y3ZGkxN1VTMWZ+dWxIRzNRMWczcFVEODc2UTd0RjcxN0Z6Y3pOUHBpYGZHSzZsNTk2TFNXNDdod29sMGwxc1l+WXB4a2c2VWg5OHgwNzZBYW56QmZuMnk5M1duen5FUFJVOEtuYnVrOHdoOWU3UjV2YUd6NFVLZ3NneTNQaU5+MkxMSzdxZmRHRkdWUE02N2kzRFVHdm9yd1JoT0V6ejFhYXNYMUkxcmBidnM1Zmw1eEcwdzlJMEc1UzExVlgzdXV+dDlacVlzQlY2UlQ1cFdHWXQwQ0k4YUZPNjg1dDl1cVEyUW05MTExZlV5VGhZfnFXRFdnc1NINTB6RUwyTTl1RWc4ckMwUTA3dFE2NWR6a2BMbkJjZDZ6SXBRZFZnMDVvcFlud1YwZWA3aHlGZHQxZmdTWGAxMzY5MGBFNmd2cFFrbDhvaE1pQkZHWTBVRTFGUDIxdFJsMGQ3YkhQczg5ZVZPR1lhMmw2MzA0YjA4NWd4Y1NkWUIwQ2Z+emh1NlVZbzEwS3htd1YxNjVjOUI0REI0QVh4RmBXNk9zeHhWdzQwRjQ3cGRHflFnbzJQYWxnT2tvWGdaTDYzQ09aMVc4Y3o4N0R5RkVZZkJWMkJzMUthS1Y4YTZyT3JmZnYxMFRjdGdhbFBkejUyM2Z6d0JnNjNjQWBHeHB6dG5lWGhNUjBWWjlgQzBYZ3BQbjdScnBmeVlzYTgyZUkyRmVweWc2NmJ0QmY5S2J6MGMzZDU5N0hWVXl1MX5VVnFLcjNmN2t4WnRtRktyR3lCMGRHRzdOfjZIbjRmYTFHSDhtVXA2NzhpMDEyc0ROOFpMenVBOWtHWTFER2R2dFlzZ0FEbzU2eEJoNzJnckl6aHFHV0lWYXV2fkVtem9YYXo2NVh1Wlk4RTA2bENgWUE0OGBnN1h6eGhSUk82eThaTnVwWDkxQ2hHUHczMDgwT1R+MDQxaXJjfjJ3M0w5Q3VsMVFNdmxzQ0FyaWkyQ3hrYDg5bkQxOFBUZTIwS1c1cDBHZE9aRnA0aXhwemM0UjN+MnY1cWR+MzJOZjlHRXgwQjlzaTQxaH5CeGgySDk3b2tvQjQ1dHJaNDBYU0FoSEQ3NVNNNnE5eUgxMnZ6ZDBFbmVtcTBxSFQ2Mk1iQnViMFJVOWFZR3FGc3kzbTlHc0J5RWJ4NXpQMEdTaDB1S2hzVmBVNHlDcHhSOFJjc0wzMnJZMjBnUXJaN2ZFaUt1cjEzWjFFYWc0R0s5eThPUWE0RER2TGNxMzBZNjBNUllpUDhnNXQ0RzgxN1cxWnBDMjFLZjFJWVl+bXpVNEs3TTRHVUJ5UlM1NURwM1NYMjZPNUU5QVNEY0taVEMyZTNNbFFnaXA3Z0xiNXFMM2R+MmlpbmduVjlLeU5lTnFHM3c0NkhRNTkyR2M2c0dhNDZnMmM3RG40QzFoSHVmMGEyfmJSWXlHRkxhVnVUOHJZR1k3dDFiN1k5b2FjUTg4bUM1RzN3bmx1NDQ1QUsybH43WEI5UFFkN0dvRHlPM08wNVlPNmtucWZLS09XUFplU3IwVEgzNXFLMUNiZEhrOH5+Wk9OdmdWeDhyQzJnTm1OdWNTOVJuekdpRVNBdmdERVhRZ2JIa0JWMDQ4UEc0T05QR1VBTnl+SU9XODZoR2xCODg0dzlPeFREeFhESDVCR1pCZlRuUlJPZE0zMmd+fmlXUzE0Mk5BbzdGbUVJOXF5RzJCYnZtVmFxdlgwWWxvU3pCYFNMR3Ewc0h1Zzd3bXM5NTRXMEs2N3NJYDQxYTMyRWE3bWlpWFdBOUV0NEdLWXI4MDdVNXg3YHUyZmtNRUFkM1lLNUFRaWdQS2JyQUd1VDZ4YXlwcjFYbmBBQW1nMENZQ2tzY0tTY21kNk9RNkxnbTk1a2Z2RzdVYGROaWdlQjYzN29mR25PR05YUEhHb2V+Z2xZRllTU2dFfkt+N3FnTDFRfkhuaXZySDlzM35MUTQzY2VzRXplSUVoeDRDZmdsZ1QxbHVzckVvd3ByS01XMDh1ejE3Z0g3OTlaNElmMzgyWG9seDA2NzlEUTdocjVMcn5SM3FDM01iOTRzOVFnUFNFYTdQOUJxOVdvbnpHS3R0cjM4VXpgNnFRNmtDR2Q5cGswMEZaOFNTc0FOWn45dTlWeU42UXAxdjloSWUxVEM1UzFHODg1SWt5dkYwZ1dNbTc5OUJYOTJnWjRzTH4welB5OWJ3d0tYVnBQRjNXQzFVU3FYUlM0MEc3VXFJcU42dzEyTjNxM1JFZ1VrbzRsMTZQNmxISXRxMEc3UXk3WjEzcG4wNVExbG1WelhWN0ZMOHF4SDdMdmBjczcwZjdJdGc2TExVZXRLOXFnS0xnZk5hNXQyd1dRU2VTNnBTYnpNd01xTGtVNnFCa0hwZjRvWGd2dDRpeVl+fjNTdHhJfm1UTW9kbkRtYjhkU2hVdnF+VVhwTml1UTRlMHpLOWhNWn5zb3c3ejJ5bE5IRGBoMHhBdENTNmw4OGgxM0s5OFRiRnZETm40ZW9pNjRgZEdsTEtQMG1GfjFlQ1NCOGA1QlVEQW4xa1NGZGcwYVFOeTVoVjQycVZBdlZTSVdrUFcxRldhNTkzNVp+TUlVVkFlMERpcjd4R0dNNjF4ejJ4dmNUeXRiVlU5WjBEQn53aEFhQzFQdzBSUEZoaHBscFYwQ2czZkJkaGxUTnpVOTczSGAxR0ZMflRVVGw1R1J6WjZndzRDQmU1dU5FVkRXQUxPMUNWek1sZjdZMmE2aDdYYWhXMnV+ZFI1cUVjRWlTOTFtcTFHOTE2aU9kUG93OEdzWjl4Q0x5VjAyQk9XT3B5NTE3bUlzbTF6cjFgclBZdTE5enlsSDMzUURQVm5ZTGt5NURGQUVUZWlwVk11ZUFyb2VRN1RVMkJ4VGw2N2c5N3Q0NFZEZng5WkhlUzhWNzRESXlUaHl2Z1JhZ0dzRER+RzRsRDd3QW9hdTc1RDhrVzAxUlhCZzZVSVFMMjc2eDJnTnZ4T2g4eHVMNjY0cEY2UzdrS0RGNEN1fnhXNmc3OURzRXpJcndPM0FnT1M1NGFLVmcxMkdvMVMwVHdUMDM3cXZlbFA0MjU3OHFUVDFZMWYxaHFTazAxREIxUGlCNnc1M0tLT29mcjJkZ2Z6WG1iNlNZYFBsU3FaM0VFMjdCZ0dNRng5V3cwMUU1WkczVjNTUWE0c3hQMW9mVnVkbzNLMEdoNFhHNDg0emdHT3Q5R2NINjJDeDk0NDAwTEk4b3FoTTdHMWd5WnFJMERSV2lXVVVQMH5ZS0MzTUkwRURCNWVzMk1ib1RjbDYya3YzNTRpNXVOMTN2ZkMydWdJUjl+cVVUR3dwV21ORlExMDNNSDY1MjU3cGJLR05aNHB2TWl3S0J1MUs0dzI3SzY5NDV1ZjFtemNGc2k0Tk1ZdktHemU1MFBCbXowPAYGKlYLBwEHBDJyTDQ0NWwxNVhyM0lEUGJCZzlsR3p3MVY0Tm4zRzQ4TTQxSVlzOXptdjQ5MjhHMFZpbDAZBgYqVgsHAQgED+ato+W4uOS8oOWFpW9pZDA8BgYqVgsHAQMEMjhJMzVJcktlR3VlYDFGR0x5WFRSWk1vZFhENWM4OHY2MjBtc2xOcXA5NGY5NWRlUjY2MDwGBipWCwcBBAQyUWkyZm5BZWY0QXBUV1J6VkFLMVkzYzBvZ2Z6ZExwcjVSR28xR1QwVnRTTUE4Yzc5a2gwPAYGKlYLBwEFBDJLYTM3STJmTTFYNkh5QU0zYFNQYTBzWTQwbkZFZzFuVDhiYGk4RlM4TE5OTHkxTUU0bDA8BgYqVgsHAQYEMlQ0YVFgdVEzNjBWUkZtVUM4VFAyMjczRFo2YmxHMnVud1JPNm1GaHpkQTN0MjEweTJZMA0GCSqGSIb3DQEBBQUAA4GBAOXI5cBPhLialA2YGwB3fwalFV00x2uMA+kcCJ0daEljqk5BkEVqa92kyk63H1yiAsfVYLLpYUnKP185w6khtu0F+it1y5/9AIaUlaE63fyTTw9cmrVmrCH9PRw5VS0DmSMY6K/jmkpmm4UIrKzM0N4M4GCR3NEDDG/Ykr5ZRvVj";
    GaiaProvider provider = GaiaUtils.instance();
    BjcaCert cert = CertificateUtil.createCert(Base64.decode(certString));
    SelfDefExtension selfDefExtension = cert.getSelfDefExtension("1.2.86.11.7.1.5");
    System.out.println(selfDefExtension);

  }


}