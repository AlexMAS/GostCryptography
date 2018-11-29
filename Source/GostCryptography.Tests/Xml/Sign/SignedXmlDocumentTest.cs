using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Gost_R3411;
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
	public sealed class SignedXmlDocumentTest
	{
		[Test]
		public void ShouldSignXml()
		{
			// Given
			var signingCertificate = TestConfig.GetCertificate();
			var xmlDocument = CreateXmlDocument();

			// When
			var signedXmlDocument = SignXmlDocument(xmlDocument, signingCertificate);

			// Then
			Assert.IsTrue(VerifyXmlDocumentSignature(signedXmlDocument));
		}

		private static XmlDocument CreateXmlDocument()
		{
			var document = new XmlDocument();
			document.LoadXml(Resources.SignedXmlExample);
			return document;
		}

		private static XmlDocument SignXmlDocument(XmlDocument xmlDocument, X509Certificate2 signingCertificate)
		{
			// Создание подписчика XML-документа
			var signedXml = new GostSignedXml(xmlDocument);

			// Установка ключа для создания подписи
			signedXml.SetSigningCertificate(signingCertificate);

			// Ссылка на весь документ и указание алгоритма хэширования
			var dataReference = new Reference { Uri = "", DigestMethod = Gost_R3411_94_HashAlgorithm.AlgorithmNameValue };

			// Метод преобразования для подписи всего документа
			dataReference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

			// Установка ссылки на узел
			signedXml.AddReference(dataReference);

			// Установка информации о сертификате, который использовался для создания подписи
			var keyInfo = new KeyInfo();
			keyInfo.AddClause(new KeyInfoX509Data(signingCertificate));
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
	}
}