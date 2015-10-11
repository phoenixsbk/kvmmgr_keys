package cn.lynx.emi.license;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;

public class GenerateKeyPairs {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		SecureRandom secrand = new SecureRandom();
		secrand.setSeed("cn.lynx.emi".getBytes());
		keygen.initialize(4096, secrand);
		KeyPair keys = keygen.genKeyPair();

		PublicKey pubkey = keys.getPublic();
		PrivateKey prikey = keys.getPrivate();

		String myPubKey = Base64.encodeBase64String(pubkey.getEncoded());
		String myPriKey = Base64.encodeBase64String(prikey.getEncoded());
		System.out.println(prikey);
		System.out.println("pubKey=" + myPubKey);
		System.out.println("priKey=" + myPriKey);
	}
}
