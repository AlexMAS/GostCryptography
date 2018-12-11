using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using GostCryptography.Pkcs;

using NUnit.Framework;

namespace GostCryptography.Tests.Pkcs
{
	/// <summary>
	/// Подпись и проверка подписи сообщения CMS/PKCS#7.
	/// </summary>
	/// <remarks>
	/// Тест создает сообщение, формирует подписанное сообщение в формате CMS/PKCS#7,
	/// а затем проверяет подпись полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи сообщения CMS/PKCS#7")]
	public class SignedCmsSignTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_Certificates))]
		public void ShouldSign(TestCertificateInfo testCase)
		{
			// Given
			var certificate = testCase.Certificate;
			var message = CreateMessage();

			// When
			var signedMessage = SignMessage(certificate, message);
			var isValidSignedMessage = VerifyMessage(signedMessage);

			// Then
			Assert.IsTrue(isValidSignedMessage);
		}

		private static byte[] CreateMessage()
		{
			// Некоторое сообщение для подписи

			return Encoding.UTF8.GetBytes("Some message to sign...");
		}

		private static byte[] SignMessage(X509Certificate2 certificate, byte[] message)
		{
			// Создание объекта для подписи сообщения
			var signedCms = new GostSignedCms(new ContentInfo(message));

			// Создание объект с информацией о подписчике
			var signer = new CmsSigner(certificate);

			// Включение информации только о конечном сертификате (только для теста)
			signer.IncludeOption = X509IncludeOption.EndCertOnly;

			// Создание подписи для сообщения CMS/PKCS#7
			signedCms.ComputeSignature(signer);

			// Создание сообщения CMS/PKCS#7
			return signedCms.Encode();
		}

		private static bool VerifyMessage(byte[] signedMessage)
		{
			// Создание объекта для проверки подписи сообщения
			var signedCms = new GostSignedCms();

			// Чтение сообщения CMS/PKCS#7
			signedCms.Decode(signedMessage);

			try
			{
				// Проверка подписи сообщения CMS/PKCS#7
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