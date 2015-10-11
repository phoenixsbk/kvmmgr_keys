package cn.lynx.emi.license;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.X509EncodedKeySpec;
import java.util.Enumeration;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

public class LicenseTest {
	private static final String LICENSE_CORE_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoc7HGhetqiAwyrVZxBskNusiz9TNPX0niaIi7C16DxnKguANpn1lDOk/U2T+gOJiLIt/zL3bvhjCXN0krD4lZUJZxC2RXSQG97622aFeYuYOKtkzmrNwlRK8RCeKlGbydF9V7O+LmKHEzlpttLx0pglw0x4ps4ALEc82wZErHhZ9m76m1ykoNOSY+Khz4OPhMVXKm0EYwitTktfSEsV/vIsXymbJCUprkN1Nw7ftjA3UyU9LvRhs1puczss8kp0WLE9gOB9dxzV+QrmLnZWVvHAF8BGsalQpOQ/KaY9hl8UIqleYqBcYa6sfX9vzbl66RVII7l30Hx2wKK6PhAs51NeGE1s3wg81fq80aC3vOhlwoAIK8w9gXKrctbg8bV0pf2uLUVkjFR63YgTsQbHJTux8fnRM99//x8quM3/g+qVVUsYBwmHbl6YEUxTyYsO+auYCLrsxBvPSa5JVXiTmDyz22NBOaDdNqjSVygyXB6nH7CZogze1IDOqbzNPy+Lu20bEAQKVXwU8kWIW22dWrNYVXDeCDYb8dkLZj9qPHIwDQeM4kgLqnEMfObvZJbgbbJ1SQ84gZ0RPFtgIic6KTel/8ToSVZRuBrz5p6Eb5J9kB1a6Xb/5uVenmtHA4y4L+he6Fuq07QRnfzTZw7Gi3hunwxPOzrQoE45MdSVD9gUCAwEAAQ==";
	
	public static void main(String[] args) throws UnsupportedEncodingException {
		if (args == null || args.length <= 0) {
			System.out.println("Machine Code:" + _generateMachineCode());
			return;
		}
		
		if (args.length == 1) {
			String license = args[0];
			LicenseBean lb = retrieveLicense(license);
			if (lb == null) {
				System.err.println("License Bean can't be serialized.");
				return;
			}
			
			System.out.println("LB Machine Code:" + lb.getMachineCode());
			System.out.println("LB CPU:" + lb.getCpuCount());
			System.out.println("LB Mem:" + lb.getMemCount());
		}
	}
	
	private static final String _generateMachineCode() {
		StringBuilder sb = new StringBuilder();
		try {
			Enumeration<NetworkInterface> enumsofnet = NetworkInterface.getNetworkInterfaces();
			while (enumsofnet.hasMoreElements()) {
				NetworkInterface nic = enumsofnet.nextElement();
				byte[] mac = nic.getHardwareAddress();
				if (mac != null) {
					sb.append(Base64.encodeBase64String(mac));
				}
			}
		} catch (SocketException e) {
		}
		return sb.toString();
	}
	
	public static final LicenseBean retrieveLicense(String license) throws UnsupportedEncodingException {
		String decryptedLicense = _decryptByPubKey(new String(Base64.decodeBase64(license), "UTF-8"));
		try {
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decryptedLicense.getBytes("UTF-8")));
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

	private static final String _decryptByPubKey(String data) throws UnsupportedEncodingException {
		return _cryptoByKey(data, Cipher.DECRYPT_MODE);
	}

	private static final String _cryptoByKey(String data, int mode) throws UnsupportedEncodingException {
		byte[] corekey = Base64.decodeBase64(LICENSE_CORE_KEY);

		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(corekey);
		System.out.println("decrypt data:" + data.getBytes("UTF-8").length);
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			Key publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(mode, publicKey);
			
			return Base64.encodeBase64String(cipher.doFinal(data.getBytes("UTF-8")));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}