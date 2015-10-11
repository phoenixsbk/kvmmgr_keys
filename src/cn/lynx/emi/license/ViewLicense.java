package cn.lynx.emi.license;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

public class ViewLicense {
	private static final String LICENSE_CORE_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoc7HGhetqiAwyrVZxBskNusiz9TNPX0niaIi7C16DxnKguANpn1lDOk/U2T+gOJiLIt/zL3bvhjCXN0krD4lZUJZxC2RXSQG97622aFeYuYOKtkzmrNwlRK8RCeKlGbydF9V7O+LmKHEzlpttLx0pglw0x4ps4ALEc82wZErHhZ9m76m1ykoNOSY+Khz4OPhMVXKm0EYwitTktfSEsV/vIsXymbJCUprkN1Nw7ftjA3UyU9LvRhs1puczss8kp0WLE9gOB9dxzV+QrmLnZWVvHAF8BGsalQpOQ/KaY9hl8UIqleYqBcYa6sfX9vzbl66RVII7l30Hx2wKK6PhAs51NeGE1s3wg81fq80aC3vOhlwoAIK8w9gXKrctbg8bV0pf2uLUVkjFR63YgTsQbHJTux8fnRM99//x8quM3/g+qVVUsYBwmHbl6YEUxTyYsO+auYCLrsxBvPSa5JVXiTmDyz22NBOaDdNqjSVygyXB6nH7CZogze1IDOqbzNPy+Lu20bEAQKVXwU8kWIW22dWrNYVXDeCDYb8dkLZj9qPHIwDQeM4kgLqnEMfObvZJbgbbJ1SQ84gZ0RPFtgIic6KTel/8ToSVZRuBrz5p6Eb5J9kB1a6Xb/5uVenmtHA4y4L+he6Fuq07QRnfzTZw7Gi3hunwxPOzrQoE45MdSVD9gUCAwEAAQ==";
	
	public static void main(String[] args) throws UnsupportedEncodingException {
		if (args == null || args.length <= 0) {
			System.err.println("Please provide the license string");
			return;
		}
		
		if (args.length == 1) {
			String license = args[0];
			LicenseBean lb = retrieveLicense(license);
			if (lb == null) {
				System.err.println("License Bean can't be deserialized.");
				return;
			}
			
			System.out.println("LB Machine Code:" + lb.getMachineCode());
			System.out.println("LB CPU:" + lb.getCpuCount());
			System.out.println("LB Mem:" + lb.getMemCount());
			System.out.println("LB Exp:" + new Date(lb.getExpireDate()));
		}
	}
	
	public static final LicenseBean retrieveLicense(String license) throws UnsupportedEncodingException {
		String decryptedLicense = _decrypt(license);
		try {
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(Base64.decodeBase64(decryptedLicense)));
			LicenseBean bean = (LicenseBean) ois.readObject();
			return bean;
		} catch (IOException e) {
			e.printStackTrace();
			return null;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			return null;
		}
	}

	private static final String _decrypt(String data){
		byte[] corekey = Base64.decodeBase64(LICENSE_CORE_KEY);
		byte[] rawData = Base64.decodeBase64(data);
		
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(corekey);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			Key publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.DECRYPT_MODE, publicKey);
			
			return new String(cipher.doFinal(rawData), "UTF-8");
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
