using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

using NUnit.Framework;

namespace GostCryptography.Tests.Gost_28147_89
{
    /// <summary>
    /// Шифрование и дешифрование данных с использованием случайного сессионного ключа ГОСТ Р 34.12-2015 Кузнечик.
    /// </summary>
    /// <remarks>
    /// Тест имитирует обмен данными между условным отправителем, который шифрует заданный поток байт, и условным получателем, который дешифрует
    /// зашифрованный поток байт. Шифрация осуществляется с использованием случайного симметричного ключа, который в свою очередь шифруется
    /// с использованием открытого ключа получателя. Соответственно для дешифрации данных сначала расшифровывается случайный симметричный ключ
    /// с использованием закрытого ключа получателя.
    /// </remarks>
    [TestFixture(Description = "Шифрование и дешифрование данных с использованием случайного сессионного ключа ГОСТ Р 34.12-2015 Кузнечик")]
    public class KuznyechikEncryptDecryptSessionKeyTest
    {
        [Test]
        [TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_Certificates))]
        public void ShouldEncryptAndDecrypt(TestCertificateInfo testCase)
        {
            // Given
            var certificate = testCase.Certificate;
            var privateKey = (GostAsymmetricAlgorithm)certificate.GetPrivateKeyAlgorithm();
            var publicKey = (GostAsymmetricAlgorithm)certificate.GetPublicKeyAlgorithm();
            var dataStream = CreateDataStream();

            // When
            var encryptedDataStream = SendEncryptedDataStream(publicKey, dataStream, out var iv, out var sessionKey);
            var decryptedDataStream = ReceiveEncryptedDataStream(privateKey, encryptedDataStream, iv, sessionKey);

            // Then
            Assert.That(dataStream, Is.EqualTo(decryptedDataStream));
        }

        private static Stream CreateDataStream()
        {
            // Некоторый поток байт

            return new MemoryStream(Encoding.UTF8.GetBytes("Some data to encrypt..."));
        }

        private static Stream SendEncryptedDataStream(GostAsymmetricAlgorithm publicKey, Stream dataStream, out byte[] iv, out byte[] sessionKey)
        {
            var encryptedDataStream = new MemoryStream();

            // Отправитель создает случайный сессионный ключ для шифрации данных
            using (var senderSessionKey = new Gost_3412_K_SymmetricAlgorithm(publicKey.ProviderType))
            {
                // Отправитель передает получателю вектор инициализации
                iv = senderSessionKey.IV;

                // Отправитель шифрует сессионный ключ и передает его получателю
                var formatter = publicKey.CreateKeyExchangeFormatter();
                sessionKey = formatter.CreateKeyExchangeData(senderSessionKey);

                // Отправитель шифрует данные с использованием сессионного ключа
                using (var encryptor = senderSessionKey.CreateEncryptor())
                {
                    var cryptoStream = new CryptoStream(encryptedDataStream, encryptor, CryptoStreamMode.Write);
                    dataStream.CopyTo(cryptoStream);
                    cryptoStream.FlushFinalBlock();
                }
            }

            encryptedDataStream.Position = 0;

            return encryptedDataStream;
        }

        private static Stream ReceiveEncryptedDataStream(GostAsymmetricAlgorithm privateKey, Stream encryptedDataStream, byte[] iv, byte[] sessionKey)
        {
            var decryptedDataStream = new MemoryStream();

            var deformatter = privateKey.CreateKeyExchangeDeformatter();

            // Получатель принимает от отправителя зашифрованный сессионный ключ и дешифрует его
            using (var receiverSessionKey = deformatter.DecryptKeyExchangeAlgorithm(sessionKey))
            {
                // Получатель принимает от отправителя вектор инициализации
                receiverSessionKey.IV = iv;

                // Получатель дешифрует данные с использованием сессионного ключа
                using (var decryptor = receiverSessionKey.CreateDecryptor())
                {
                    var cryptoStream = new CryptoStream(encryptedDataStream, decryptor, CryptoStreamMode.Read);
                    cryptoStream.CopyTo(decryptedDataStream);
                }
            }

            decryptedDataStream.Position = 0;

            return decryptedDataStream;
        }
    }
}