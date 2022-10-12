using System.Collections;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

public class Client
{
    private const string SECU_KEY = "TestSampleKey";

    public static void Main(String[] args)
    {
        StartClient();
        return;
    }

    public static void StartClient()
    {
        byte[] bytes = new byte[1024];

        try
        {
            bool exit = false;
            IPHostEntry host = Dns.GetHostEntry("127.0.0.1");
            IPAddress ipAddress = host.AddressList[0];
            IPEndPoint remoteEP = new IPEndPoint(ipAddress, 11000);
            Socket sender = new Socket(ipAddress.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            try
            {
                sender.Connect(remoteEP);
                Console.WriteLine("Socket connected to {0}",
                sender.RemoteEndPoint.ToString());
                do
                {
                    switch (DisplayMenu().ToString())
                    {
                        case "1":

                            #region Brut
                            byte[] msgBRUT = Encoding.ASCII.GetBytes("BRUT<F>");
                            int bytesSentBRUT = sender.Send(msgBRUT);
                            int bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Server: {0}", Encoding.ASCII.GetString(bytes, 0, bytesRec));

                            byte[] msg = Encoding.ASCII.GetBytes("This is a test<F>");
                            int bytesSent = sender.Send(msg);

                            // Receive the response from the remote device.
                            bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Echoed test = {0}", Encoding.ASCII.GetString(bytes, 0, bytesRec));

                            #endregion Brut

                            break;

                        case "2":

                            #region DES
                            byte[] msgTDES = Encoding.ASCII.GetBytes("TRIPLEDES<F>");
                            int bytesSentTDES = sender.Send(msgTDES);
                            bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Server: {0}", Encoding.ASCII.GetString(bytes, 0, bytesRec));

                            byte[] msg1 = Encoding.ASCII.GetBytes(DES_Encrypt("This is a test") + "<F>");
                            int bytesSent1 = sender.Send(msg1);

                            // Receive the response from the remote device.
                            int bytesRec1 = sender.Receive(bytes);
                            Console.WriteLine("Echoed test = {0}", Encoding.ASCII.GetString(bytes, 0, bytesRec1));

                            #endregion DES

                            break;

                        case "3":

                            #region AES
                            byte[] msgAES = Encoding.ASCII.GetBytes("AES<F>");
                            int bytesSentAES = sender.Send(msgAES);
                            bytesRec = sender.Receive(bytes);
                            Console.WriteLine("Server: {0}", Encoding.ASCII.GetString(bytes, 0, bytesRec));
                            byte[] msg2 = AES_encrypt("This is a test", SECU_KEY);
                            string strAES = Encoding.ASCII.GetString(msg2) + "<F>";
                            Console.WriteLine(strAES);
                            byte[] msgAES2 = Encoding.ASCII.GetBytes(strAES);
                            Console.WriteLine("-----------TEST------------");
                            string msgTEST = Encoding.ASCII.GetString(msgAES2);
                            //Console.WriteLine(AES_Decrypt(msgTEST, SECU_KEY));
                            Console.WriteLine("---------------------------");
                            int bytesSent2 = sender.Send(msgAES2);

                            // Receive the response from the remote device.
                            int bytesRec2 = sender.Receive(bytes);
                            Console.WriteLine("Echoed test = {0}", Encoding.ASCII.GetString(bytes, 0, bytesRec2));
                            #endregion
                            break;

                        case "4":
                            break;

                        case "5":

                            exit = true;

                            break;

                        default:
                            break;
                    }
                }
                while (exit == false);
            }
            catch (ArgumentNullException ane)
            {
                Console.WriteLine("ArgumentNullException : {0}", ane.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
            }
        }
        catch (Exception e)
        {
            Console.WriteLine(e.ToString());
        }
    }

    public static string DES_Encrypt(string TextToEncrypt)
    {
        byte[] MyEncryptedArray = Encoding.UTF8.GetBytes(TextToEncrypt); //transfo string en bytes
        /*
        MD5CryptoServiceProvider MyMD5CryptoService = new MD5CryptoServiceProvider();
        byte[] MysecurityKeyArray = MyMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SECU_KEY));
        Console.WriteLine(BitConverter.ToString(MysecurityKeyArray));
        
        MyMD5CryptoService.Clear();
        //md5 hash la clé
        */
        PasswordDeriveBytes pdb = new PasswordDeriveBytes(SECU_KEY, null);
        var MyTripleDESCryptoService = new TripleDESCryptoServiceProvider();
        MyTripleDESCryptoService.BlockSize = 64;
        MyTripleDESCryptoService.KeySize = 192;
        MyTripleDESCryptoService.Key = pdb.CryptDeriveKey("TripleDES", "SHA1", 192, MyTripleDESCryptoService.IV);
        Console.WriteLine(Convert.ToBase64String(MyTripleDESCryptoService.Key));
        //MyTripleDESCryptoService.Key = MysecurityKeyArray;
        MyTripleDESCryptoService.Mode = CipherMode.ECB;
        MyTripleDESCryptoService.Padding = PaddingMode.PKCS7;

        var MyCrytpoTransform = MyTripleDESCryptoService.CreateEncryptor(MyTripleDESCryptoService.Key, MyTripleDESCryptoService.IV);
        byte[] MyresultArray = MyCrytpoTransform.TransformFinalBlock(MyEncryptedArray, 0, MyEncryptedArray.Length);

        MyTripleDESCryptoService.Clear();
        Console.WriteLine(Convert.ToBase64String(MyresultArray, 0, MyresultArray.Length));

        return Convert.ToBase64String(MyresultArray, 0, MyresultArray.Length);
    }

    public static byte[] AES_encrypt(string plainText, string pass)
    {
        //test debut d'encryption 
        byte[] MyEncryptedArray = Encoding.ASCII.GetBytes(plainText); //transfo string en bytes
        /*
        MD5CryptoServiceProvider MyMD5CryptoService = new MD5CryptoServiceProvider();
        byte[] MysecurityKeyArray = MyMD5CryptoService.ComputeHash(UTF8Encoding.UTF8.GetBytes(SECU_KEY));
        Console.WriteLine(BitConverter.ToString(MysecurityKeyArray));
        
        MyMD5CryptoService.Clear();
        //md5 hash la clé
        */
        byte[] encrypted, Key, IV;

        UnicodeEncoding UE = new UnicodeEncoding();
        
        using (Aes aesAlg = Aes.Create())
        {
            byte[] passwordBytes = UE.GetBytes(pass);
            Key = SHA256Managed.Create().ComputeHash(passwordBytes);
            IV = MD5.Create().ComputeHash(passwordBytes);
            aesAlg.Key = Key;
            aesAlg.Mode = CipherMode.ECB;
            aesAlg.Padding = PaddingMode.PKCS7;
            aesAlg.IV = IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(MyEncryptedArray, 0, MyEncryptedArray.Length);
                }
                encrypted = msEncrypt.ToArray();
            }
        }
        //test à la fin de l'encryption
        Console.WriteLine(Encoding.ASCII.GetString(encrypted));
        return encrypted;
    }
    public static string AES_Decrypt(string TextToDecrypt, string pass)
    {
        TextToDecrypt = TextToDecrypt.Remove(TextToDecrypt.Length - 3);
        byte[] cipherText = Encoding.ASCII.GetBytes(TextToDecrypt);
        Console.WriteLine(TextToDecrypt);
        Console.WriteLine(cipherText.Length);
        string plaintext;

        // Create an Aes object
        // with the specified key and IV.
        byte[] Key, IV;
        UnicodeEncoding UE = new UnicodeEncoding();
        using (Aes aesAlg = Aes.Create())
        {
            byte[] passwordBytes = UE.GetBytes(pass);
            Key = SHA256Managed.Create().ComputeHash(passwordBytes);
            IV = MD5.Create().ComputeHash(passwordBytes);
            aesAlg.Key = Key;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.Zeros;
            aesAlg.IV = IV;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                {
                    csDecrypt.Write(cipherText, 0, cipherText.Length);
                }
                byte[] tmp = msDecrypt.ToArray();
                plaintext = Encoding.ASCII.GetString(tmp);
            }
        }
        return plaintext;
    }


    public static int DisplayMenu()
    {
        Console.WriteLine("Crypto - CLIENT");
        Console.WriteLine();
        Console.WriteLine("1. Communication Brut");
        Console.WriteLine("2. Communication TripleDES");
        Console.WriteLine("3. Communication AES");
        Console.WriteLine("4. à venir");
        Console.WriteLine("5. Exit");
        var result = Console.ReadLine();
        return Convert.ToInt32(result);
    }
}