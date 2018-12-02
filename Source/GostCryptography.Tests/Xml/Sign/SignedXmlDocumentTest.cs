using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Sign
{
	/// <summary>
	/// Подпись и проверка подписи всего XML документа с использованием сертификата
	/// </summary>
	/// <remarks>
	/// Тест создает XML-документ, подписывает весь документ с использованием сертификата,
	/// а затем проверяет полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи всего XML документа с использованием сертификата")]
	public class SignedXmlDocumentTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Certificates))]
		public void ShouldSignXml(TestCertificateInfo testCase)
		{
			// Given

			var certificate = testCase.Certificate;

			if (certificate == null)
			{
				Assert.Ignore("Certificate not found.");
			}

			var xmlDocument = CreateXmlDocument();

			// When
			var signedXmlDocument = SignXmlDocument(xmlDocument, certificate);

			// Then
			Assert.IsTrue(VerifyXmlDocumentSignature(signedXmlDocument));
		}

		private static XmlDocument CreateXmlDocument()
		{
			var document = new XmlDocument();
			document.LoadXml(Resources.SignedXmlExample);
			return document;
		}

		private static XmlDocument SignXmlDocument(XmlDocument xmlDocument, X509Certificate2 certificate)
		{
			// Создание подписчика XML-документа
			var signedXml = new GostSignedXml(xmlDocument);

			// Установка ключа для создания подписи
			signedXml.SetSigningCertificate(certificate);

			// Ссылка на весь документ и указание алгоритма хэширования
			var dataReference = new Reference { Uri = "", DigestMethod = GetDigestMethod(certificate) };

			// Метод преобразования для подписи всего документа
			dataReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

			// Установка ссылки на узел
			signedXml.AddReference(dataReference);

			// Установка информации о сертификате, который использовался для создания подписи
			var keyInfo = new KeyInfo();
			keyInfo.AddClause(new KeyInfoX509Data(certificate));
			signedXml.KeyInfo = keyInfo;

			// Вычисление подписи
			signedXml.ComputeSignature();

			// Получение XML-представления подписи
			var signatureXml = signedXml.GetXml();

			// Добавление подписи в исходный документ
			xmlDocument.DocumentElement.AppendChild(xmlDocument.ImportNode(signatureXml, true));

			return xmlDocument;
		}

		private static bool VerifyXmlDocumentSignature(XmlDocument signedXmlDocument)
		{
			// Создание подписчика XML-документа
			var signedXml = new GostSignedXml(signedXmlDocument);

			// Поиск узла с подписью
			var nodeList = signedXmlDocument.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);

			// Загрузка найденной подписи
			signedXml.LoadXml((XmlElement)nodeList[0]);

			// Проверка подписи
			return signedXml.CheckSignature();
		}

		private static string GetDigestMethod(X509Certificate2 certificate)
		{
			// Имя алгоритма вычисляем динамически, чтобы сделать код теста универсальным

			using (var publicKey = (GostAsymmetricAlgorithm)certificate.GetPublicKeyAlgorithm())
			using (var hashAlgorithm = publicKey.CreateHashAlgorithm())
			{
				return hashAlgorithm.AlgorithmName;
			}
		}
	}
}