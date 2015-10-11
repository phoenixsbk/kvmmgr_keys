package cn.lynx.emi.license;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

public class GenerateLicense {
	private static final String LICENSE_CORE_KEY = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAoc7HGhetqiAwyrVZxBskNusiz9TNPX0niaIi7C16DxnKguANpn1lDOk/U2T+gOJiLIt/zL3bvhjCXN0krD4lZUJZxC2RXSQG97622aFeYuYOKtkzmrNwlRK8RCeKlGbydF9V7O+LmKHEzlpttLx0pglw0x4ps4ALEc82wZErHhZ9m76m1ykoNOSY+Khz4OPhMVXKm0EYwitTktfSEsV/vIsXymbJCUprkN1Nw7ftjA3UyU9LvRhs1puczss8kp0WLE9gOB9dxzV+QrmLnZWVvHAF8BGsalQpOQ/KaY9hl8UIqleYqBcYa6sfX9vzbl66RVII7l30Hx2wKK6PhAs51NeGE1s3wg81fq80aC3vOhlwoAIK8w9gXKrctbg8bV0pf2uLUVkjFR63YgTsQbHJTux8fnRM99//x8quM3/g+qVVUsYBwmHbl6YEUxTyYsO+auYCLrsxBvPSa5JVXiTmDyz22NBOaDdNqjSVygyXB6nH7CZogze1IDOqbzNPy+Lu20bEAQKVXwU8kWIW22dWrNYVXDeCDYb8dkLZj9qPHIwDQeM4kgLqnEMfObvZJbgbbJ1SQ84gZ0RPFtgIic6KTel/8ToSVZRuBrz5p6Eb5J9kB1a6Xb/5uVenmtHA4y4L+he6Fuq07QRnfzTZw7Gi3hunwxPOzrQoE45MdSVD9gUCAwEAAQ==";
	
	public static void main(String[] args) throws ClassNotFoundException {
		if (args == null || args.length != 3) {
			System.err.println("Please provide [machine code] [cpu] [memory in gb] as parameter");
			return;
		}
		
		InputStream is = GenerateLicense.class.getResourceAsStream("/privatekey");
		BufferedReader br = new BufferedReader(new InputStreamReader(is));
		String key = null;
		try {
			key = br.readLine();
		} catch (IOException e) {
			System.err.println("Can't read the private key file, make sure there's a file named \"privatekey\" in the root classpath");
			e.printStackTrace();
			return;
		}
		
		if (key == null) {
			System.err.println("Can't read the private key file, make sure there's a file named \"privatekey\" in the root classpath");
			return;
		}
		
		String machineCode = args[0];
		int cpu = Integer.parseInt(args[1]);
		long mem = Long.parseLong(args[2]);
		
		LicenseBean lb = new LicenseBean();
		lb.setCpuCount(cpu);
		lb.setMemCount(mem);
		lb.setMachineCode(machineCode);
		
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			ObjectOutputStream os = new ObjectOutputStream(baos);
			os.writeObject(lb);
			os.close();
			String serializedLicense = new String(baos.toByteArray());
			System.out.println("Machine Code is:" + machineCode);
			System.out.println("Serialized Data:" + serializedLicense);
			System.out.println("Data len:" + serializedLicense.getBytes("UTF-8").length);
			String ll = encrypt(key, serializedLicense);
			System.out.println("License:" + encrypt(key, serializedLicense));
			String dl = decrypt(ll);
			System.out.println("Decrypt License:" + decrypt(ll));
			ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(dl.getBytes()));
			LicenseBean bean = (LicenseBean) ois.readObject();
			System.out.println("bean:" + bean);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private static final String encrypt(String key, String data) {
		byte[] corekey = Base64.decodeBase64(key);

		PKCS8EncodedKeySpec pkspec = new PKCS8EncodedKeySpec(corekey);
		
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			Key privateKey = keyFactory.generatePrivate(pkspec);

			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
			byte[] encData = cipher.doFinal(data.getBytes("UTF-8"));
			System.out.println("after encrypt, len=" + encData.length);
			return Base64.encodeBase64String(encData);
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
	
	private static final String decrypt(String data) {
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
