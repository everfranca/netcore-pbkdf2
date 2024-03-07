using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PBKDF2Tools;

public class Service : IService
{
     public string CreateSalt(int size)
     {
         SecureRandom _cryptoRandom = new SecureRandom();
         byte[] salt = new byte[size];
         _cryptoRandom.NextBytes(salt);
    
         return Convert.ToBase64String(salt);
     }
     
     public string GetHash(string password, string saltAsBase64String, int iterations, int hashByteSize)
     {
         var saltBytes = Convert.FromBase64String(saltAsBase64String);
    
         var hash = GetHash(password, saltBytes, iterations, hashByteSize);
    
         return Convert.ToBase64String(hash);
     }
     
     public byte[] GetHash(string password, byte[] salt, int iterations, int hashByteSize)
     {
         var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha256Digest());
         pdb.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), salt, iterations);
    
         var key = (KeyParameter)pdb.GenerateDerivedMacParameters(hashByteSize * 8);
         return key.GetKey();
     }
     
     public bool ValidatePassword(string password, byte[] saltBytes, int iterations, int hashByteSize, byte[] actualGainedHasAsByteArray)
     {
         byte[] testHash = GetHash(password, saltBytes, iterations, hashByteSize);
         return SlowEquals(actualGainedHasAsByteArray, testHash);
     }
     
     public bool SlowEquals(byte[] item1, byte[] item2)
     {
         uint diff = (uint)item1.Length ^ (uint)item2.Length;
         for (int i = 0; i < item1.Length && i < item2.Length; i++)
             diff |= (uint)(item1[i] ^ item2[i]);
         return diff == 0;
     }
     
     public string EncryptPassword(string password, string salt)
     {
         string newPass = GetHash(password, salt, 10000, 32);
         return newPass;
     }
}