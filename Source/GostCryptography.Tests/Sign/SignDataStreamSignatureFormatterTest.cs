using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using GostCryptography.Base;

using NUnit.Framework;

namespace GostCryptography.Tests.Sign
{
	/// <summary>
	/// Подпись и проверка подписи потока байт с помощью сертификата и классов форматирования.
	/// </summary>
	/// <remarks>
	/// Тест создает поток байт, вычисляет цифровую подпись потока байт с использованием закрытого ключа сертификата,
	/// а затем с помощью открытого ключа сертификата проверяет полученную подпись. Для вычисления цифровой подписи
	/// используется класс <see cref="GostSignatureFormatter"/>, для проверки цифровой подписи используется класс
	/// <see cref="GostSignatureDeformatter"/>.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи потока байт с помощью сертификата и классов форматирования")]
	public class SignDataStreamSignatureFormatterTest
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

		private static byte[] CreateSignature(GostAsymmetricAlgorithm privateKey, Stream dataStream)
		{
			byte[] hash;

			using (var hashAlg = privateKey.CreateHashAlgorithm())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			var formatter = new GostSignatureFormatter(privateKey);

			return formatter.CreateSignature(hash);
		}

		private static bool VerifySignature(GostAsymmetricAlgorithm publicKey, Stream dataStream, byte[] signature)
		{
			byte[] hash;

			using (var hashAlg = publicKey.CreateHashAlgorithm())
			{
				hash = hashAlg.ComputeHash(dataStream);
			}

			var deformatter = new GostSignatureDeformatter(publicKey);

			return deformatter.VerifySignature(hash, signature);
		}
	}
}