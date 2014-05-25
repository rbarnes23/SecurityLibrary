package com.securitylibrary;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang3.RandomStringUtils;

public class SecurityLibrary {
	/**
	 * This method generates a unique id
	 * 
	 * @param length
	 *            of id to generater.
	 * @return String The unique id
	 * @exception None.
	 * @see None
	 */
	// generateUniqueId creates a unique id for each user...may be used for
	// other purposes later
	public static String generateUniqueId(int length) {
		return RandomStringUtils.randomAlphanumeric(length);
	}

	/**
	 * This method gets the mother boards serial #
	 * 
	 * @param None
	 * @return String The serial#
	 * @exception None.
	 * @see None
	 */
	public static String getMotherBoardSerialNumber() {
		String result = "";
		try {
			File file = File.createTempFile("realhowto", ".vbs");
			file.deleteOnExit();
			FileWriter fw = new java.io.FileWriter(file);
			String vbs = "Set objWMIService = GetObject(\"winmgmts:\\\\.\\root\\cimv2\")\n"
					+ "Set colItems = objWMIService.ExecQuery _ \n"
					+ "   (\"Select * from Win32_BaseBoard\") \n"
					+ "For Each objItem in colItems \n"
					+ "    Wscript.Echo objItem.SerialNumber \n"
					+ "    exit for  ' do the first cpu only! \n" + "Next \n";

			fw.write(vbs);
			fw.close();
			Process p = Runtime.getRuntime().exec(
					"cscript //NoLogo " + file.getPath());
			BufferedReader input = new BufferedReader(new InputStreamReader(
					p.getInputStream()));
			String line;
			while ((line = input.readLine()) != null) {
				result += line;
			}
			input.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result.trim();
	}

	/**
	 * This method gets the Hard Disk Serial#
	 * 
	 * @param None
	 * @return String The Hard Disk Serial#
	 * @exception None.
	 * @see None
	 */
	public static String getHardDiskSerialNumber(String drive) {
		String result = "";
		try {
			File file = File.createTempFile("realhowto", ".vbs");
			file.deleteOnExit();
			FileWriter fw = new java.io.FileWriter(file);

			String vbs = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
					+ "Set colDrives = objFSO.Drives\n"
					+ "Set objDrive = colDrives.item(\""
					+ drive
					+ "\")\n"
					+ "Wscript.Echo objDrive.SerialNumber"; // see note
			fw.write(vbs);
			fw.close();
			Process p = Runtime.getRuntime().exec(
					"cscript //NoLogo " + file.getPath());
			BufferedReader input = new BufferedReader(new InputStreamReader(
					p.getInputStream()));
			String line;
			while ((line = input.readLine()) != null) {
				result += line;
			}
			input.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result.trim();
	}

	/**
	 * This method gets the Local IP Address
	 * 
	 * @param None
	 * @return String The Local IP Address
	 * @exception None.
	 * @see None
	 */
	public static String getIPAddress() {
		String strIP = "127.0.0.1";
		try {
			InetAddress ip = InetAddress.getLocalHost();
			strIP = ip.getHostAddress();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return strIP;
	}

	/**
	 * This method gets the MAC Address
	 * 
	 * @param None
	 * @return String The Local MAC Address
	 * @exception None.
	 * @see None
	 */
	public static String getMACAddress() {
		String strMAC = "127.0.0.1";
		try {
			InetAddress ip = InetAddress.getLocalHost();
			NetworkInterface network = NetworkInterface.getByInetAddress(ip);
			byte[] mac = network.getHardwareAddress();
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < mac.length; i++) {
				sb.append(String.format("%02X%s", mac[i],
						(i < mac.length - 1) ? "-" : ""));
			}
			strMAC = sb.toString();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return strMAC;
	}

	/**
	 * USAGE EXAMPLE String dataToEncryptDecrypt = "android"; String
	 * encryptionDecryptionKey = "1234567812345678"; String ivs = "12345678";
	 * 
	 * byte[] encryptedData = encrypt(dataToEncryptDecrypt.getBytes("UTF-8"),
	 * encryptionDecryptionKey.getBytes("UTF-8"), ivs.getBytes()); // here you
	 * will get the encrypted bytes. Now you can use Base64 encoding on these
	 * bytes, before sending to your web-service
	 * 
	 * byte[] decryptedData = decrypt(encryptedData,
	 * encryptionDecryptionKey.getBytes(), ivs.getBytes());
	 * System.out.println(new String(decryptedData));
	 */

	/**
	 * This method encrypts data
	 * 
	 * @param data
	 *            -to encrypt,key-secret key,ivs - initialization vector
	 * @return ByteArray
	 * @exception General.
	 * @see None
	 */

	public static String encryptString(String data,
			String encryptionDecryptionKey, String ivs) {
		String encryptedString = "";
		byte[] encryptedData;
		try {
			encryptedData = encrypt(data.getBytes("UTF-8"),
					encryptionDecryptionKey.getBytes("UTF-8"),
					ivs.getBytes("UTF-8"));
			encryptedString = Base64.encodeBytes(encryptedData, Base64.GZIP);//encodeToString(encryptedData,false);
			// encryptedString = new String(encryptedData, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encryptedString;

	}

	public static String decryptString(String data,
			String encryptionDecryptionKey, String ivs) {
		String decryptedString = "";
		byte[] decryptedData;
		try {
			byte[] decrypted = Base64.decode(data);
			decryptedData = decrypt(decrypted,
					encryptionDecryptionKey.getBytes("UTF-8"),
					ivs.getBytes("UTF-8"));
			 decryptedString = new String(decryptedData, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return decryptedString;
	}

	public static byte[] encrypt(byte[] data, byte[] key, byte[] ivs) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			byte[] finalIvs = new byte[16];
			int len = ivs.length > 16 ? 16 : ivs.length;
			System.arraycopy(ivs, 0, finalIvs, 0, len);
			IvParameterSpec ivps = new IvParameterSpec(finalIvs);
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivps);
			return cipher.doFinal(data);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * This method decrypts data
	 * 
	 * @param data
	 *            -to encrypt,key-secret key,ivs - initialization vector
	 * @return ByteArray
	 * @exception General.
	 * @see None
	 */
	public static byte[] decrypt(byte[] data, byte[] key, byte[] ivs) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
			byte[] finalIvs = new byte[16];
			int len = ivs.length > 16 ? 16 : ivs.length;
			System.arraycopy(ivs, 0, finalIvs, 0, len);
			IvParameterSpec ivps = new IvParameterSpec(finalIvs);
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivps);
			return cipher.doFinal(data);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
}
