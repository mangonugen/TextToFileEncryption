using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace TextToFileEncryption
{
    /// <summary>
    /// Author: Man Nguyen
    /// </summary>
    public class Encryption
    {
        private const string SaltKey = "s@ltedK3y";
        private const string IvKey = "1V3ct0rk3y";

        #region Encrypt String to file and file back to string
        /// <summary>
        /// Encrypt string into a file using Triple DES
        /// </summary>
        /// <param name="originalString">String to be encrypted </param>
        /// <param name="outputFilePath">Full file path for the output</param>
        /// <param name="saltKey">Salted key</param>
        /// <param name="ivKey">Initialization vector key</param>
        /// <remarks>Cross platform with Java encryption</remarks>
        public static void Encrypt3DesTextToFile(string originalString, string outputFilePath, string saltKey, string ivKey)
        {
            try
            {
                var key = string.IsNullOrEmpty(saltKey) ? SaltKey : saltKey;
                var iv = string.IsNullOrEmpty(ivKey) ? IvKey : ivKey;
                
                using(var fsEncrypted = new FileStream(outputFilePath, FileMode.Create, FileAccess.Write))
                using (var cTransform = Create3DesProvider(CryptoTransformType.Encrypt, key, iv))
                {
                    using (var cryptoStream = new CryptoStream(fsEncrypted, cTransform, CryptoStreamMode.Write))
                    {
                        //Read in the input file, and then write out to the output file
                        byte[] bytearrayinput = ASCIIEncoding.UTF8.GetBytes(originalString);
                        cryptoStream.Write(bytearrayinput, 0, bytearrayinput.Length);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.ToString());
                throw;
            }
        }

        /// <summary>
        /// Decrypt file to string using Triple DES
        /// </summary>
        /// <param name="inputFilePath">Full file path of the encrypted file</param>
        /// <param name="saltKey">Salted key</param>
        /// <param name="ivKey">Initialization vector key</param>
        /// <returns>Decrypted string</returns>
        /// <remarks>Cross platform with Java decryption</remarks>
        public static string Decrypt3DesFileToText(string inputFilePath, string saltKey, String ivKey)
        {
            try
            {
                var key = string.IsNullOrEmpty(saltKey) ? SaltKey : saltKey;
                var iv = string.IsNullOrEmpty(ivKey) ? IvKey : ivKey;

                //Create a file stream to read the encrypted file back.
                using(var fsread = new FileStream(inputFilePath, FileMode.Open, FileAccess.Read))
                //Create a DES decryptor from the DES instance.
                using (var cTransform = Create3DesProvider(CryptoTransformType.Decrypt, key, iv))
                {
                    //Create crypto stream set to read and do a 
                    //DES decryption transform on incoming bytes.
                    using (var cryptoStream = new CryptoStream(fsread, cTransform, CryptoStreamMode.Read))
                    {
                        using (var sr = new StreamReader(cryptoStream))
                        {
                            return sr.ReadToEnd();
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.ToString());
                throw;
            }
        }
        #endregion

        #region Private methods
        /// <summary>
        /// Helper method to create 3DES CrytoTransform Interface
        /// </summary>
        /// <param name="cryptoType">Encrypt or decrypt</param>
        /// <param name="saltedKey">Salted key</param>
        /// <param name="ivKey">Initialization vector key</param>
        /// <returns>Triple DES encryptor or decryptor object</returns>
        private static ICryptoTransform Create3DesProvider(CryptoTransformType cryptoType, string saltedKey, string ivKey)
        {
            try
            {
                byte[] keyBytes = CreateSha512Bytes(saltedKey, 24);
                byte[] ivBytes = CreateSha512Bytes(ivKey, 8);

                using (var tripleDes = new TripleDESCryptoServiceProvider() { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
                {
                    switch (cryptoType)
                    {
                        case CryptoTransformType.Encrypt:
                            return tripleDes.CreateEncryptor(keyBytes, ivBytes);
                        case CryptoTransformType.Decrypt:
                            return tripleDes.CreateDecryptor(keyBytes, ivBytes);
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex.ToString());
                throw;
            }

            return null;
        }

        /// <summary>
        /// This is a helper method to create digest bytes up to 64 bytes array
        /// </summary>
        /// <param name="key">Value to transform into SHA 512 byte array</param>
        /// <param name="copyLength">The length to copy</param>
        /// <returns>SHA 512 byte array</returns>
        private static byte[] CreateSha512Bytes(string key, int copyLength)
        {
            using (var sha512 = new SHA512CryptoServiceProvider())
            {
                var digestIv = sha512.ComputeHash(Encoding.UTF8.GetBytes(key));
                var bLength = (copyLength > 64) ? 64 : copyLength;
                var ivBytes = new byte[bLength];
                Array.Copy(digestIv, ivBytes, bLength);
                return ivBytes;
            }
        }
        #endregion
    }
}
