using System.IO;
using System.Security.Cryptography;
using System.Text;

using GostCryptography.Cryptography;

using NUnit.Framework;

namespace GostCryptography.Tests.Sign
{
	/// <summary>
	/// Подпись и проверка подписи потока байт с помощью сертификата и информации об алгоритме цифровой подписи
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет цифровую подпись потока байт с использованием закрытого ключа сертификата,
	/// а затем с помощью открытого ключа сертификата проверяет полученную подпись. Для вычисления цифровой подписи
	/// и ее проверки используется информация об алгоритме цифровой подписи <see cref="SignatureDescription"/> 
	/// (<see cref="GostSignatureDescription"/>), получаемая с помощью метода <see cref="GostCryptoConfig.CreateFromName"/>.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи потока байт с помощью сертификата и информации об алгоритме цифровой подписи")]
	public sealed class SignDataStreamSignatureDescriptionTest
	{
		[Test]
		public void ShouldSignDataStream()
		{
			// Given
			var certificate = TestCertificates.GetCertificate();
			var privateKey = certificate.GetPrivateKeyAlgorithm();
			var publicKey = certificate.GetPrivateKeyAlgorithm();
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

		private static byte[] CreateSignature(AsymmetricAlgorithm privateKey, Stream dataStream)
		{
			var signatureDescription = (SignatureDescription)GostCryptoConfig.CreateFromName(privateKey.SignatureAlgorithm);

			byte[] hash;

			using (var hashAlg = signatureDescription.CreateDigest())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			var formatter = signatureDescription.CreateFormatter(privateKey);
			formatter.SetHashAlgorithm(signatureDescription.DigestAlgorithm);

			return formatter.CreateSignature(hash);
		}

		private static bool VerifySignature(AsymmetricAlgorithm publicKey, Stream dataStream, byte[] signature)
		{
			var signatureDescription = (SignatureDescription)GostCryptoConfig.CreateFromName(publicKey.SignatureAlgorithm);

			byte[] hash;

			using (var hashAlg = signatureDescription.CreateDigest())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			var deformatter = signatureDescription.CreateDeformatter(publicKey);
			deformatter.SetHashAlgorithm(signatureDescription.DigestAlgorithm);

			return deformatter.VerifySignature(hash, signature);
		}
	}
}