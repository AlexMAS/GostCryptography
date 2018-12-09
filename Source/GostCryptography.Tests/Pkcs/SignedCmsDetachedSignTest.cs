using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using GostCryptography.Pkcs;

using NUnit.Framework;

namespace GostCryptography.Tests.Pkcs
{
	/// <summary>
	/// Подпись и проверка отсоединенной подписи сообщения CMS/PKCS#7.
	/// </summary>
	/// <remarks>
	/// Тест создает сообщение, формирует отсоединенную подпись сообщения в формате CMS/PKCS#7,
	/// а затем проверяет подпись полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка отсоединенной подписи сообщения CMS/PKCS#7")]
	public class SignedCmsDetachedSignTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Certificates))]
		public void ShouldSign(TestCertificateInfo testCase)
		{
			// Given
			var certificate = testCase.Certificate;
			var message = CreateMessage();

			// When
			var detachedSignature = SignMessage(certificate, message);
			var isValidDetachedSignature = VerifyMessage(message, detachedSignature);

			// Then
			Assert.IsTrue(isValidDetachedSignature);
		}

		private static byte[] CreateMessage()
		{
			// Некоторое сообщение для подписи

			return Encoding.UTF8.GetBytes("Some message to sign...");
		}

		private static byte[] SignMessage(X509Certificate2 certificate, byte[] message)
		{
			// Создание объекта для подписи сообщения
			var signedCms = new GostSignedCms(new ContentInfo(message), true);

			// Создание объект с информацией о подписчике
			var signer = new CmsSigner(certificate);

			// Включение информации только о конечном сертификате (только для теста)
			signer.IncludeOption = X509IncludeOption.EndCertOnly;

			// Создание подписи для сообщения CMS/PKCS#7
			signedCms.ComputeSignature(signer);

			// Создание подписи CMS/PKCS#7
			return signedCms.Encode();
		}

		private static bool VerifyMessage(byte[] message, byte[] detachedSignature)
		{
			// Создание объекта для проверки подписи сообщения
			var signedCms = new GostSignedCms(new ContentInfo(message), true);

			// Чтение подписи CMS/PKCS#7
			signedCms.Decode(detachedSignature);

			try
			{
				// Проверка подписи CMS/PKCS#7
				signedCms.CheckSignature(true);
			}
			catch
			{
				return false;
			}

			return true;
		}
	}
}