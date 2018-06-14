using System.Collections.Generic;
using System;

namespace filebrowser
{
    class Dictionary
    {
        public static Dictionary<string, string> keys = new Dictionary<string, string>();

        //add a value to the dictionary
        public void add(string hash, string key)
        {
            try
            {
                keys.Add(hash,key);

                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();

                var fi = new System.IO.FileInfo(@"C:\crypto\aeskeys\keys.bin");

                {
                    //ToDo file override insted of create 
                    using (var binaryFile = fi.Create())
                    {
                        binaryFormatter.Serialize(binaryFile, keys);
                        binaryFile.Flush();
                    }
                }

                //ToDo Logging
            }

            catch (Exception ex)
            {
                //ToDo Logging
            }
        }

        //read key from the dictionary
        public string find(string hash)
        {
            try
            {
            
                string key;
                var binaryFormatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();

                var fi = new System.IO.FileInfo(@"C:\crypto\aeskeys\keys.bin");

                Dictionary<string, string> readBack;
                using (var binaryFile = fi.OpenRead())
                {
                    readBack = (Dictionary<string, string>)binaryFormatter.Deserialize(binaryFile);
                }

                keys.TryGetValue(hash, out key);
            
                //ToDo Logging

                return key;

            }


            catch (Exception ex)
            {
                //ToDo Logging
                return null;
            }

        }

    }
}
