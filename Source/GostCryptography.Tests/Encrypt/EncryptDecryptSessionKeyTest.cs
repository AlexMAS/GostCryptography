using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

using NUnit.Framework;

namespace GostCryptography.Tests.Encrypt
{
	/// <summary>
	/// Шифрование и дешифрование данных с использованием случайного сессионного ключа.
	/// </summary>
	/// <remarks>
	/// Тест имитирует обмен данными между условным отправителем, который шифрует заданный поток байт, и условным получателем, который дешифрует 
	/// зашифрованный поток байт. Шифрация осуществляется с использованием случайного симметричного ключа, который в свою очередь шифруется 
	/// с использованием открытого ключа получателя. Соответственно для дешифрации данных сначало расшифровывается случайный симметричный ключ 
	/// с использованием закрытого ключа получателя.
	/// </remarks>
	[TestFixture(Description = "Шифрование и дешифрование данных с использованием случайного сессионного ключа")]
	public sealed class EncryptDecryptSessionKeyTest
	{
		private GostAsymmetricAlgorithm _publicKey;
		private GostAsymmetricAlgorithm _privateKey;

		[SetUp]
		public void SetUp()
		{
			var certificate = TestConfig.FindGostCertificate(c => c.IsGost_R3410_2012_256());

			// Отправитель имеет открытый асимметричный ключ для шифрации сессионного ключа
			_publicKey = (GostAsymmetricAlgorithm)certificate.GetPublicKeyAlgorithm();

			// Получатель имеет закрытый асимметричный ключ для дешифрации сессионного ключа
			_privateKey = (GostAsymmetricAlgorithm)certificate.GetPrivateKeyAlgorithm();
		}

		[TearDown]
		public void TearDown()
		{
			try
			{
				_publicKey.Dispose();
			}
			finally
			{
				_publicKey = null;
			}

			try
			{
				_privateKey.Dispose();
			}
			finally
			{
				_privateKey = null;
			}
		}

		[Test]
		public void ShouldEncryptAndDecrypt()
		{
			// Given
			var publicKey = _publicKey;
			var privateKey = _privateKey;
			var dataStream = CreateDataStream();

			// When
			var encryptedDataStream = SendEncryptedDataStream(publicKey, dataStream, out var iv, out var sessionKey);
			var decryptedDataStream = ReceiveEncryptedDataStream(privateKey, encryptedDataStream, iv, sessionKey);

			// Then
			Assert.IsTrue(CompareDataStream(dataStream, decryptedDataStream));
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for encrypt..."));
		}

		private static Stream SendEncryptedDataStream(GostAsymmetricAlgorithm publicKey, Stream dataStream, out byte[] iv, out byte[] sessionKey)
		{
			var encryptedDataStream = new MemoryStream();

			// Отправитель создает случайный сессионный ключ для шифрации данных
			using (var senderSessionKey = new Gost_28147_89_SymmetricAlgorithm())
			{
				// Отправитель передает получателю вектор инициализации
				iv = senderSessionKey.IV;

				// Отправитель шифрует сессионный ключ и передает его получателю
				var formatter = publicKey.CreatKeyExchangeFormatter();
				sessionKey = formatter.CreateKeyExchangeData(senderSessionKey);

				// Отправитель шифрует данные с использованием сессионного ключа
				using (var encryptor = senderSessionKey.CreateEncryptor())
				{
					var cryptoStream = new CryptoStream(encryptedDataStream, encryptor, CryptoStreamMode.Write);
					dataStream.CopyTo(cryptoStream);
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

		private static bool CompareDataStream(Stream expected, Stream actual)
		{
			if (expected.Length == actual.Length)
			{
				expected.Position = 0;
				var expectedBytes = new byte[expected.Length];
				expected.Read(expectedBytes, 0, expectedBytes.Length);

				actual.Position = 0;
				var actualBytes = new byte[actual.Length];
				actual.Read(actualBytes, 0, actualBytes.Length);

				return expectedBytes.SequenceEqual(actualBytes);
			}

			return false;
		}
	}
}