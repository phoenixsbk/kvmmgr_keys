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
import java.text.ParseException;
import java.text.SimpleDateFormat;

import javax.crypto.Cipher;

import org.apache.commons.codec.binary.Base64;

public class GenerateLicense {
	public static void main(String[] args) throws ClassNotFoundException, ParseException {
		if (args == null || args.length != 4) {
			System.err.println("Please provide [machine code] [cpu] [memory in gb] [yyyy-MM-dd] as parameter");
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
		long mem = Long.parseLong(args[2]) * 1024 * 1024 * 1024;
		SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
		long expDate = sdf.parse(args[3]).getTime();
		
		LicenseBean lb = new LicenseBean();
		lb.setCpuCount(cpu);
		lb.setMemCount(mem);
		lb.setMachineCode(machineCode);
		lb.setExpireDate(expDate);
		
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			ObjectOutputStream os = new ObjectOutputStream(baos);
			os.writeObject(lb);
			os.close();
			
			String serializedLicense = Base64.encodeBase64String(baos.toByteArray());
			System.out.println("License:" + encrypt(key, serializedLicense));
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
}
