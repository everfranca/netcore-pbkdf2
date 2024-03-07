using PBKDF2Tools;

namespace Tests
{
    public class Tests
    {
        private IService _service;
        private string Salt { get; set; } = string.Empty;
        private string Password { get; set; } = "ABC@123";
        private string EncryptedPassword { get; set; } = string.Empty;

        [SetUp]
        public void Setup()
        {
            _service = new Service();
        }

        [Test]
        public void EncryptPassword()
        {
            var salt = _service.CreateSalt(256 / 8);
            var password = _service.EncryptPassword(password: Password, salt: salt);

            Salt = salt;
            EncryptedPassword = password;
            Assert.Multiple(() =>
            {
                Assert.That(salt, Is.Not.Null);
                Assert.That(password, Is.Not.Null);
            });
        }


        [Test]
        public void VerifyPassword()
        {
            var newPassword = _service.GetHash(password: Password, saltAsBase64String: Salt, iterations: 10000, hashByteSize: 256 / 8);
            var isEquals = _service.SlowEquals(Convert.FromBase64String(EncryptedPassword), Convert.FromBase64String(newPassword));
            
            Assert.That(isEquals, Is.EqualTo(true));
        }
    }
}