using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Gost_R3410;
using GostCryptography.Gost_R3411;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Sign
{
	/// <summary>
	/// Подпись и проверка подписи XML-документа с использованием контейнера ключей.
	/// </summary>
	/// <remarks>
	/// Тест создает XML-документ, подписывает определенную часть данного документа с использованием контейнера ключей, 
	/// а затем проверяет полученную цифровую подпись.
	/// </remarks>
	[TestFixture(Description = "Подпись и проверка подписи XML-документа с использованием контейнера ключей")]
	public sealed class SignedXmlKeyContainerTest
	{
		[Test]
		public void ShouldSignXml()
		{
			// Given
			var keyContainer = TestCertificates.GetKeyContainer();
			var signingKey = new Gost_R3410_2001_AsymmetricAlgorithm(keyContainer);
			var xmlDocument = CreateXmlDocument();

			// When
			var signedXmlDocument = SignXmlDocument(xmlDocument, signingKey);

			// Then
			Assert.IsTrue(VerifyXmlDocumentSignature(signedXmlDocument));
		}

		private static XmlDocument CreateXmlDocument()
		{
			var document = new XmlDocument();
			document.LoadXml(Resources.SignedXmlExample);
			return document;
		}

		private static XmlDocument SignXmlDocument(XmlDocument xmlDocument, GostAsymmetricAlgorithm signingKey)
		{
			// Создание подписчика XML-документа
			var signedXml = new GostSignedXml(xmlDocument);

			// Установка ключа для создания подписи
			signedXml.SigningKey = signingKey;

			// Ссылка на узел, который нужно подписать, с указанием алгоритма хэширования
			var dataReference = new Reference { Uri = "#Id1", DigestMethod = Gost_R3411_94_HashAlgorithm.AlgorithmNameValue };

			// Установка ссылки на узел
			signedXml.AddReference(dataReference);

			// Установка информации о ключе, который использовался для создания подписи
			var keyInfo = new KeyInfo();
			keyInfo.AddClause(new GostKeyValue(signingKey));
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