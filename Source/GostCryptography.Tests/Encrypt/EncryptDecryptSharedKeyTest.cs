using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using GostCryptography.Cryptography;

using NUnit.Framework;

namespace GostCryptography.Tests.Encrypt
{
	/// <summary>
	/// Шифрование и дешифрование данных с использованием общего симметричного ключа.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, шифрует его с использованием общего симметричного ключа, а затем дешифрует
	/// зашифрованные данные и проверяет корректность дешифрации.
	/// </remarks>
	[TestFixture(Description = "Шифрование и дешифрование данных с использованием общего симметричного ключа")]
	public sealed class EncryptDecryptSharedKeyTest
	{
		private Gost28147SymmetricAlgorithmBase _sharedKey;

		[SetUp]
		public void SetUp()
		{
			_sharedKey = new Gost28147SymmetricAlgorithm();
		}

		[TearDown]
		public void TearDown()
		{
			try
			{
				_sharedKey.Dispose();
			}
			finally
			{
				_sharedKey = null;
			}
		}

		[Test]
		public void ShouldEncryptAndDecrypt()
		{
			// Given
			var sharedKey = _sharedKey;
			var dataStream = CreateDataStream();

			// When
			var encryptedDataStream = EncryptDataStream(sharedKey, dataStream);
			var decryptedDataStream = DecryptDataStream(sharedKey, encryptedDataStream);

			// Then
			Assert.IsTrue(CompareDataStream(dataStream, decryptedDataStream));
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for encrypt..."));
		}

		private static Stream EncryptDataStream(SymmetricAlgorithm sharedKey, Stream dataStream)
		{
			var encryptedDataStream = new MemoryStream();

			using (var encryptor = sharedKey.CreateEncryptor())
			{
				var cryptoStream = new CryptoStream(encryptedDataStream, encryptor, CryptoStreamMode.Write);
				dataStream.CopyTo(cryptoStream);
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