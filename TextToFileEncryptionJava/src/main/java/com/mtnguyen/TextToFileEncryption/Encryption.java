package com.mtnguyen.TextToFileEncryption;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.base.Strings;

public class Encryption {
	private static final String SaltKey = "s@ltedK3y";	
	private static final String IvKey = "1V3ct0rk3y";
	
	/**
  	 * This method encrypt string to file using Triple DES
  	 * @param originalString String to be encrypted
  	 * @param strOutputFilePath Full file path for the output 
  	 * @param saltKey Salted key
  	 * @param ivKey Initialization vector key
  	 * @author Man Nguyen
	 * @throws Exception 
  	 * @remark Cross platform with C# encryption
  	 */
  	public static void encrypt3DesTextToFile(String originalString, String strOutputFilePath, String saltKey, String ivKey) throws Exception
	{		
		try(FileOutputStream fos = new FileOutputStream(strOutputFilePath)) {
			String key = Strings.isNullOrEmpty(saltKey) ? SaltKey : saltKey; //need to be 24 bytes
	        String iv = Strings.isNullOrEmpty(ivKey) ? IvKey : ivKey ; //need to be 8 bytes
	        	        	        
	        byte[] plainText = originalString.getBytes(); //get byte from message
	        
			//Create triple DES cipher instance
	        Cipher c3des = create3DesCipher(key, iv, Cipher.ENCRYPT_MODE); 
	        //Writing the cipher to the file
	        try(CipherOutputStream cos = new CipherOutputStream(fos, c3des)) {
	        	cos.write(plainText, 0, plainText.length);
	        }			
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} 
	}
  	
  	/**
  	 * This method decrypt file to string using Triple DES
  	 * @param strInputFilePath Full file path of the encrypted file
  	 * @param saltKey Salted key
  	 * @param ivKey Initialization vector key
  	 * @return Decrypted string
  	 * @author Man Nguyen
  	 * @throws Exception 
  	 * @remark Cross platform with C# encryption
  	 */
	public static String decrypt3DesFileToText(String strInputFilePath, String saltKey, String ivKey) throws Exception
	{
		try(InputStream fis = new FileInputStream(strInputFilePath)) {			
			String key = Strings.isNullOrEmpty(saltKey) ? SaltKey : saltKey; //need to be 24 bytes
	        String iv = Strings.isNullOrEmpty(ivKey) ? IvKey : ivKey ; //need to be 8 bytes
	        
			//Create triple DES cipher instance
	        Cipher c3des = create3DesCipher(key, iv, Cipher.DECRYPT_MODE); 
						
			try(CipherInputStream cis = new CipherInputStream(fis, c3des)) {		        
		        ByteArrayOutputStream baos = new ByteArrayOutputStream();
		    	byte[] buffer = new byte[fis.available()];
		    	int numRead;	    	
				//Reading and decrypt cipher from the file
		    	while ((numRead = cis.read(buffer)) >= 0) {
		    		baos.write(buffer, 0, numRead);
		    	}
		    	
		    	return new String(baos.toByteArray());
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw e;
		} 
	}
  	
  	/**
     * This is helper method to create Triple DES Cipher
     * @param saltKey Salted key
     * @param ivKey Initialization vector key
     * @param cipherMode Encrypt or decrypt mode
     * @return Cipher to encrypt or decrypt depend on cipher mode
     * @throws Exception
     * @author Man Nguyen
     */
    private static Cipher create3DesCipher(String saltKey, String ivKey, int cipherMode) throws Exception {
    	final byte[] keyBytes = createSha512Bytes(saltKey, 24);
        final byte[] ivBytes = createSha512Bytes(ivKey, 8);
        
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, "DESede");
        IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
        cipher.init(cipherMode, secretKeySpec, ivParameterSpec);        
        return cipher;
    }
    
    /**
     * This is a helper method to create iv bytes
     * @param input Value to transform into SHA 512 byte array
     * @param copyLength The length to copy
     * @return SHA 512 byte array
     * @author Man Nguyen
     */
    private static byte[] createSha512Bytes(String input, int copyLength)
    {
    	byte[] digestIV = getDigestBytes("SHA-512", input); //64 bytes
    	final int bLength = (copyLength > 64) ? 64 : copyLength; 
    	return Arrays.copyOf(digestIV, bLength);    	
    }
    
    /**
     * This is a helper method to create digest bytes.
     * @param algorithm Name of the algorithm
     * @param input Value to transform into SHA 512 byte array
     * @return Byte array of digest key
     * @author Man Nguyen
     */
    private static byte[] getDigestBytes(String algorithm, String input)
    {
    	try {
			return MessageDigest.getInstance(algorithm).digest(input.getBytes("utf-8"));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
    	return null;
    }
}
