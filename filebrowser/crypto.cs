/**
 * 
 * The class crypto provide the main crypto functionality for the asymetric en- and decryption 
 * 
 * Keys() generate a new rsa keypair 
         * @param string publicKeyFileName
         * @param string privateKeyFileName
 *
 * Encrypt() encrypt a rsa file with the public key and store the new file to the given path
         * @param string publicKeyFileName
         * @param string plainFileName
         * @param string encryptedFileName
* 
 * Decrypt() decrypt a rsa file with the private key and store the new file to the given path
         * @param string privateKeyFileName
         * @param string encryptedFileName
         * @param string plainFileName
* 
 * The class_symetric crypto provide the main symetric crypto functionality for the en- and decryption 
 *
 * symetrEncrypt() encrypt a aes file with the public key and store the new file to the given path
 * The Key and the IV will be also stored in a file 
         * @param string fileInputPath
         * @param string fileOutputPath
         * @param string fileOutputKeyPath
         * @param string fileOutputIVPath
* 
 * symetrDecrypt() decrypt a aes file with the private key and store the new file to the given path
         * @param string fileInputPath
         * @param string fileOutputPath
 *
 * The class md5 has only one function. Building a md5 Hash of a file 
 *
 * buildmd5() build the md5 hash and bring it back 
         * @param string filePath
 **/

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;


namespace filebrowser
{
    class crypto
    {
        // Generate a new rsa keypair
        public static void Keys(string publicKeyFileName, string privateKeyFileName)

        {

            // Variables

            CspParameters cspParams = null;

            RSACryptoServiceProvider rsaProvider = null;

            StreamWriter publicKeyFile = new StreamWriter(Path.Combine(@"C:\crypto\rsakeys", publicKeyFileName));

            StreamWriter privateKeyFile = new StreamWriter(Path.Combine(@"C:\crypto\rsakeys", privateKeyFileName));

            string publicKey = "";

            string privateKey = "";


            try

            {

                // Create a new key pair on target CSP

                cspParams = new CspParameters();

                cspParams.ProviderType = 1; // PROV_RSA_FULL

                //cspParams.ProviderName; // CSP name

                cspParams.Flags = CspProviderFlags.UseArchivableKey;

                cspParams.KeyNumber = (int)KeyNumber.Exchange;

                rsaProvider = new RSACryptoServiceProvider(cspParams);


                // Export public key

                publicKey = rsaProvider.ToXmlString(false);


                // Write public key to file

                publicKeyFile.Write(publicKey);


                // Export private/public key pair

                privateKey = rsaProvider.ToXmlString(true);


                // Write private/public key pair to file

                privateKeyFile.Write(privateKey);

                //ToDo Logging

            }

            catch (Exception ex)

            {
                //ToDo Logging
                // Any errors? Show them

            }

            finally

            {

                // Do some clean up if needed

                if (publicKeyFile != null)

                {

                    publicKeyFile.Close();

                }

                if (privateKeyFile != null)

                {

                    privateKeyFile.Close();

                }

            }


        }

        // Encrypt a rsa file
        public static string Encrypt(byte[] decryptedKey)

        {
            try

            {

                CspParameters cspParams = new CspParameters();
                cspParams.ProviderType = 1; // PROV_RSA_FULL
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider(cspParams);
                StreamReader publicKeyFile = File.OpenText(@"C:\crypto\rsakeys\" + System.Environment.MachineName + ".pub");
                string publicKeyText = publicKeyFile.ReadToEnd();
                publicKeyFile.Close();
                provider.FromXmlString(publicKeyText);
                byte[] encryptedKeyByte = provider.Encrypt(decryptedKey, false);
                string encryptedKey = Convert.ToBase64String(encryptedKeyByte);

                return encryptedKey;
            }

            catch (Exception ex)

            {
                //ToDo Logging
                return null;

            }
        }
        
        // Decrypt a rsa file
        public static byte[] Decrypt(string encryptedKey)

        {
            try
            {
                //creat new CspParameter container
                CspParameters cspParams = null;
                cspParams = new CspParameters();

                cspParams.ProviderType = 1; // PROV_RSA_FULL
                RSACryptoServiceProvider provider = new RSACryptoServiceProvider(cspParams);
                StreamReader privateKeyFile = File.OpenText(@"C:\crypto\rsakeys\" + System.Environment.MachineName + ".ppk");
                string privateKeyText = privateKeyFile.ReadToEnd();
                privateKeyFile.Close();
                provider.FromXmlString(privateKeyText);
                byte[] encryptedKeyByte = Convert.FromBase64String(encryptedKey);
                byte[]  plainBytes = provider.Decrypt(encryptedKeyByte, false);
                return plainBytes;
            }
            catch (Exception ex)

            {
                return null;
                //ToDo Logging

            }

        }

    }

    class crypto_symmetric
    {
        Dictionary keys = new Dictionary();
        md5 hash = new md5();

        //Method to encrypt files with symetric aes
        public void symetrEncrypt(string fileInputPath, string fileOutputPath)
        {
            try
            {
                using (RijndaelManaged RMCrypto = new RijndaelManaged())
                {
                    RMCrypto.KeySize = 256;
                    RMCrypto.BlockSize = 256;
                    
                    RMCrypto.GenerateKey();

                    //Create file for new crypt document 
                    using (FileStream fsCrypt = new FileStream(fileOutputPath, FileMode.Create))
                    {
                        using (ICryptoTransform encryptor = RMCrypto.CreateEncryptor(RMCrypto.Key, RMCrypto.Key))
                        {
                            //new CryptoStream to stream a file like a filestream but used for crypto data 
                            using (CryptoStream cs = new CryptoStream(fsCrypt, encryptor, CryptoStreamMode.Write))
                            {
                                //Create FileStream to open and Save data in the while statment
                                using (FileStream fsIn = new FileStream(fileInputPath, FileMode.Open))
                                {
                                    int data;
                                    while ((data = fsIn.ReadByte()) != -1)
                                    {
                                        cs.WriteByte((byte)data);
                                    }
                                }
                            }
                        }
                    }
                    
                    keys.add(hash.buildmd5(fileOutputPath), crypto.Encrypt(RMCrypto.Key));
                }

                //ToDo Logging
            }
            catch (Exception ex)
            {
                //ToDO logging 
            }
        }

        //Method to decrypt files with a symetric aes
        public void symetrDecrypt(string fileInputPath, string fileOutputPath)
        {
            try
            {
                using (RijndaelManaged aes = new RijndaelManaged())
                {
                    aes.KeySize = 256;
                    aes.BlockSize = 256;
                    //Read aes keys
                    string key = keys.find(hash.buildmd5(fileInputPath));
                    byte[] decryptetKey = crypto.Decrypt(key);

                    //Read exist crypted file 
                    using (FileStream fsCrypt = new FileStream(fileInputPath, FileMode.Open))
                    {
                        //New filestream to save the decrypted file as a new file
                        using (FileStream fsOut = new FileStream(fileOutputPath, FileMode.Create))
                        {
                            using (ICryptoTransform decryptor = aes.CreateDecryptor(decryptetKey, decryptetKey))
                            {
                                //read encrypted file and save it in a new file withe the same name 
                                using (CryptoStream cs = new CryptoStream(fsCrypt, decryptor, CryptoStreamMode.Read))
                                {
                                    int data;
                                    while ((data = cs.ReadByte()) != -1)
                                    {
                                        fsOut.WriteByte((byte)data);
                                    }
                                }
                            }
                        }
                    }
                }

                //ToDo Logging
            }

            catch (Exception ex)
            {
                //ToDo logging
            }
        }
    }

    class md5
    {
        //Build a MD5 Hash of a file and return it as string
        public string buildmd5(string filePath)
        {
            try
            {
                using (var md5 = MD5.Create())
                {
                    using (var stream = File.OpenRead(filePath))
                    {
                        var hash = md5.ComputeHash(stream);
                        return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
                    }
                }
            }

            catch (Exception ex)
            {
                //ToDo Loggin
                return null;
            }
        }
    }
}
