using System.IO;
using System.Security.Cryptography;
using System.Text;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

using NUnit.Framework;

namespace GostCryptography.Tests.Gost_28147_89
{
	/// <summary>
	/// Шифрование и дешифрование данных с использованием общего симметричного ключа ГОСТ 28147-89.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, шифрует его с использованием общего симметричного ключа,
	/// а затем дешифрует зашифрованные данные и проверяет корректность дешифрации.
	/// </remarks>
	[TestFixture(Description = "Шифрование и дешифрование данных с использованием общего симметричного ключа ГОСТ 28147-89")]
	public class Gost_28147_89_SymmetricAlgorithmTest
	{
		[Test]
		[TestCase(TestConfig.ProviderType)]
		[TestCase(TestConfig.ProviderType_2012_512)]
		[TestCase(TestConfig.ProviderType_2012_1024)]
		public void ShouldEncryptAndDecrypt(ProviderTypes providerType)
		{
			// Given
			var sharedKey = new Gost_28147_89_SymmetricAlgorithm(providerType);
			var dataStream = CreateDataStream();

			// When
			var encryptedDataStream = EncryptDataStream(sharedKey, dataStream);
			var decryptedDataStream = DecryptDataStream(sharedKey, encryptedDataStream);

			// Then
			Assert.That(dataStream, Is.EqualTo(decryptedDataStream));
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data to encrypt..."));
		}

		private static Stream EncryptDataStream(SymmetricAlgorithm sharedKey, Stream dataStream)
		{
			var encryptedDataStream = new MemoryStream();

			using (var encryptor = sharedKey.CreateEncryptor())
			{
				var cryptoStream = new CryptoStream(encryptedDataStream, encryptor, CryptoStreamMode.Write);
				dataStream.CopyTo(cryptoStream);
				cryptoStream.FlushFinalBlock();
			}

			encryptedDataStream.Position = 0;

			return encryptedDataStream;
		}

		private static Stream DecryptDataStream(SymmetricAlgorithm sharedKey, Stream encryptedDataStream)
		{
			var decryptedDataStream = new MemoryStream();

			using (var decryptor = sharedKey.CreateDecryptor())
			{
				var cryptoStream = new CryptoStream(encryptedDataStream, decryptor, CryptoStreamMode.Read);
				cryptoStream.CopyTo(decryptedDataStream);
				decryptedDataStream.Flush();
			}

			decryptedDataStream.Position = 0;

			return decryptedDataStream;
		}
	}
}