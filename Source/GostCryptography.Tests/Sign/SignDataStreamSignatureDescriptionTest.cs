using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using GostCryptography.Base;
using GostCryptography.Config;

using NUnit.Framework;

namespace GostCryptography.Tests.Sign
{
	/// <summary>
	/// Подпись и проверка подписи потока байт с помощью сертификата и информации об алгоритме цифровой подписи
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет цифровую подпись потока байт с использованием закрытого ключа сертификата,
	/// а затем с помощью открытого ключа сертификата проверяет полученную подпись. Для вычисления цифровой подписи
	/// и ее проверки используется информация об алгоритме цифровой подписи <see cref="SignatureDescription"/>,
	/// получаемая с помощью метода <see cref="GostCryptoConfig.CreateFromName"/>.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи потока байт с помощью сертификата и информации об алгоритме цифровой подписи")]
	public class SignDataStreamSignatureDescriptionTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_Certificates))]
		public void ShouldSignDataStream(TestCertificateInfo testCase)
		{
			// Given
			var certificate = testCase.Certificate;
			var privateKey = (GostAsymmetricAlgorithm)certificate.GetPrivateKeyAlgorithm();
			var publicKey = (GostAsymmetricAlgorithm)certificate.GetPublicKeyAlgorithm();
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

			return new MemoryStream(Encoding.UTF8.GetBytes("Some data to sign..."));
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