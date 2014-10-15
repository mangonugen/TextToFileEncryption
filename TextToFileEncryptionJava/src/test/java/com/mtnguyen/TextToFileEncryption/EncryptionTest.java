package com.mtnguyen.TextToFileEncryption;

import java.io.FileNotFoundException;

import org.junit.Test;

import static org.junit.Assert.*;

public class EncryptionTest 
{
	@Test
	public void encryptAndDecrypt_EmptyIvSalt_Success() throws Exception
	{
		final String filePath = new java.io.File( "." ).getCanonicalPath() + "\\" + "encryptedFile.txt",
				orginalString = "Some message need to be encrypt",
				saltKey = "",
				ivKey = "";
		
		Encryption.encrypt3DesTextToFile(orginalString, filePath, saltKey, ivKey);
		String result = Encryption.decrypt3DesFileToText(filePath, saltKey, ivKey);
		assertEquals(orginalString, result);
	}
	
	@Test
	public void encryptAndDecrypt_IvSalt_Success() throws Exception
	{
		final String filePath = new java.io.File( "." ).getCanonicalPath() + "\\" + "encryptedFile.txt",
				orginalString = "Some message need to be encrypt",
				saltKey = "s0meS@ltk3y",
				ivKey = "S0me1vK3y";
		
		Encryption.encrypt3DesTextToFile(orginalString, filePath, saltKey, ivKey);
		String result = Encryption.decrypt3DesFileToText(filePath, saltKey, ivKey);
		assertEquals(orginalString, result);
	}
		
	@Test(expected = FileNotFoundException.class)
	public void decrypt_FileNotFoundException() throws Exception
	{
		final String filePath = "Debug\\encryptedFile.txt",
				saltKey = "",
				ivKey = "";
				
		Encryption.decrypt3DesFileToText(filePath, saltKey, ivKey);
	}
	
	@Test
	public void encryptAndDecrypt_Exception() throws Exception
	{
		final String filePath = new java.io.File( "." ).getCanonicalPath() + "\\" + "encryptedFile.txt",
				orginalString = "Some message need to be encrypt",
				saltKey = "",
				ivKey = "";
		
		Encryption.encrypt3DesTextToFile(orginalString, filePath, saltKey, ivKey);
		String result = Encryption.decrypt3DesFileToText(filePath, "saltkey", "ivKey");
		assertNotEquals(orginalString, result);
	}
}
