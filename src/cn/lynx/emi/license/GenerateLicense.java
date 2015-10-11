package cn.lynx.emi.license;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

public class GenerateLicense {
	public static void main(String[] args) {
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
			String serializedLicense = new String(baos.toByteArray(), "UTF-8");
			System.out.println("Data len:" + serializedLicense.getBytes().length);
			System.out.println("License:" + _encryptByPriKey(key, serializedLicense));
		} catch (IOException e) {
		}
	}
	
	private static final String _encryptByPriKey(String key, String data) {
		return _cryptoByKey(key, data, Cipher.ENCRYPT_MODE);
	}

	private static final String _cryptoByKey(String key, String data, int mode) {
		byte[] corekey = Base64.decodeBase64(key);

		PKCS8EncodedKeySpec pkspec = new PKCS8EncodedKeySpec(corekey);
		
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			Key privateKey = keyFactory.generatePrivate(pkspec);

			Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
			cipher.init(mode, privateKey);
			
			return Base64.encodeBase64String(cipher.doFinal(data.getBytes("UTF-8")));
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}
}
