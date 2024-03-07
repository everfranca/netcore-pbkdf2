namespace PBKDF2Tools;

public interface IService
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="size"></param>
    /// <returns>Salt base64 string</returns>
    public string CreateSalt(int size);
    public string GetHash(string password, string saltAsBase64String, int iterations, int hashByteSize);
    public byte[] GetHash(string password, byte[] salt, int iterations, int hashByteSize);
    public bool ValidatePassword(string password, byte[] saltBytes, int iterations, int hashByteSize, byte[] actualGainedHasAsByteArray);
    public bool SlowEquals(byte[] item1, byte[] item2);
    public string EncryptPassword(string password, string salt);
}