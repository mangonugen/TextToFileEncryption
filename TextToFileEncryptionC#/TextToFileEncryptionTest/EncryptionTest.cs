using System;
using System.Diagnostics;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using TextToFileEncryption;

namespace TextToFileEncryptionTest
{
    [TestClass]
    public class EncryptionTest
    {
        [TestMethod]
        public void EncryptAndDecrypt_EmptyIvSalt_Success()
        {
            var filePath = AppDomain.CurrentDomain.BaseDirectory + "\\" + "encryptedFile.txt";
            const string originalString = "Some message need to be encrypt",
                         saltKey = "",
                         ivKey = "";
            
            Encryption.Encrypt3DesTextToFile(originalString, filePath, saltKey, ivKey);
            var result = Encryption.Decrypt3DesFileToText(filePath, saltKey, ivKey);
            Assert.AreEqual(originalString, result);
        }

        [TestMethod]
        public void EncryptAndDecrypt_IvSalt_Success()
        {
            var filePath = AppDomain.CurrentDomain.BaseDirectory + "\\" + "encryptedFile.txt";
            const string originalString = "Some message need to be encrypt",
                         saltKey = "s0meS@ltk3y",
                         ivKey = "S0me1vK3y";

            Encryption.Encrypt3DesTextToFile(originalString, filePath, saltKey, ivKey);
            var result = Encryption.Decrypt3DesFileToText(filePath, saltKey, ivKey);
            Assert.AreEqual(originalString, result);
        }

        [TestMethod]
        [ExpectedException(typeof(System.IO.DirectoryNotFoundException))]
        public void EncryptAndDecrypt_IvSalt_DirectoryNotFoundException()
        {
            var filePath = @"Debug\encryptedFile.txt";
            const string saltKey = "",
                         ivKey = "";

            Encryption.Decrypt3DesFileToText(filePath, saltKey, ivKey);
        }

        [TestMethod]
        [ExpectedException(typeof(System.IO.FileNotFoundException))]
        public void EncryptAndDecrypt_IvSalt_DirectoryNotFoundException1()
        {
            var filePath = @"encryptedFile112.txt";
            const string saltKey = "",
                         ivKey = "";

            Encryption.Decrypt3DesFileToText(filePath, saltKey, ivKey);
        }

        [TestMethod]
        public void EncryptAndDecrypt_EmptyIvSalt_Ex()
        {
            var filePath = AppDomain.CurrentDomain.BaseDirectory + "\\" + "encryptedFile.txt";
            const string originalString = "Some message need to be encrypt",
                         saltKey = "",
                         ivKey = "";

            Encryption.Encrypt3DesTextToFile(originalString, filePath, saltKey, ivKey);
            var result = Encryption.Decrypt3DesFileToText(filePath, "saltKey", "ivKey");
            Assert.AreNotEqual(originalString, result);
        }
    }
}
