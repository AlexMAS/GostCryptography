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
	/// Тест создает сообщение, формирует подписанное сообщение в формате CMS/PKCS#7, а затем проверяет
	/// подпись полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи сообщения CMS/PKCS#7")]
	public sealed class SignedCmsSignTest
	{
		[Test]
		public void ShouldSign()
		{
			// Given
			var certificate = TestCertificates.GetCertificate();
			var message = CreateMessage();

			// When
			var signedMessage = SignMessage(certificate, message);
			var isValudSignedMessage = VerifyMessage(signedMessage);

			// Then
			Assert.IsTrue(isValudSignedMessage);
		}

		private static byte[] CreateMessage()
		{
			// Некоторое сообщение для подписи

			return Encoding.UTF8.GetBytes("Some message for sign...");
		}

		private static byte[] SignMessage(X509Certificate2 certificate, byte[] message)
		{
			// Создание объекта для подписи сообщения
			var signedCms = new GostSignedCms(new ContentInfo(message));

			// Создание объектс с информацией о подписчике
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