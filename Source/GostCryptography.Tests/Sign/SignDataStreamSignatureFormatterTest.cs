using System.IO;
using System.Text;

using GostCryptography.Cryptography;

using NUnit.Framework;

namespace GostCryptography.Tests.Sign
{
	/// <summary>
	/// Подпись и проверка подписи потока байт с помощью сертификата и классов формтирования.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет цифровую подпись потока байт с использованием закрытого ключа сертификата,
	/// а затем с помощью открытого ключа сертификата проверяет полученную подпись. Для вычисления цифровой подписи
	/// используется класс <see cref="GostSignatureFormatter"/>, для проверки цифровой подписи используется класс
	/// <see cref="GostSignatureDeformatter"/>.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи потока байт с помощью сертификата и классов формтирования")]
	public sealed class SignDataStreamSignatureFormatterTest
	{
		[Test]
		public void ShouldSignDataStream()
		{
			// Given
			var certificate = TestCertificates.GetCertificate();
			var privateKey = (Gost3410AsymmetricAlgorithmBase)certificate.GetPrivateKeyAlgorithm();
			var publicKey = (Gost3410AsymmetricAlgorithmBase)certificate.GetPrivateKeyAlgorithm();
			var dataStream = CreateDataStream();

			// When

			dataStream.Seek(0, SeekOrigin.Begin);
			var signature = CreateSignature(privateKey, dataStream);

			dataStream.Seek(0, SeekOrigin.Begin);
			var isValidSignature = VerifySignature(publicKey, dataStream, signature);

			// Then
			Assert.IsTrue(isValidSignature);
		}

		private static Stream CreateDataStream()
		{
			// Некоторый поток байт для подписи

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data for sign..."));
		}

		private static byte[] CreateSignature(Gost3410AsymmetricAlgorithmBase privateKey, Stream dataStream)
		{
			byte[] hash;

			using (var hashAlg = new Gost3411HashAlgorithm())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			var formatter = new GostSignatureFormatter(privateKey);

			return formatter.CreateSignature(hash);
		}

		private static bool VerifySignature(Gost3410AsymmetricAlgorithmBase publicKey, Stream dataStream, byte[] signature)
		{
			byte[] hash;

			using (var hashAlg = new Gost3411HashAlgorithm())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			var deformatter = new GostSignatureDeformatter(publicKey);

			return deformatter.VerifySignature(hash, signature);
		}
	}
}