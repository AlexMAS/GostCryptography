using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Gost_R3410;
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
	public class SignedXmlKeyContainerTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2001_Certificates))]
		public void ShouldSignXmlWithGost_R3410_2001(TestCertificateInfo testCase)
		{
			// Given
			var certificate = testCase.Certificate;
			var keyContainer = certificate.GetPrivateKeyInfo();
			var signingKey = new Gost_R3410_2001_AsymmetricAlgorithm(keyContainer);
			var xmlDocument = CreateXmlDocument();

			// When
			var signedXmlDocument = SignXmlDocument(xmlDocument, signingKey);

			// Then
			Assert.IsTrue(VerifyXmlDocumentSignature(signedXmlDocument));
		}

		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2012_256_Certificates))]
		public void ShouldSignXmlWithGost_R3410_2012_256(TestCertificateInfo testCase)
		{
			// Given
			var certificate = testCase.Certificate;
			var keyContainer = certificate.GetPrivateKeyInfo();
			var signingKey = new Gost_R3410_2012_256_AsymmetricAlgorithm(keyContainer);
			var xmlDocument = CreateXmlDocument();

			// When
			var signedXmlDocument = SignXmlDocument(xmlDocument, signingKey);

			// Then
			Assert.IsTrue(VerifyXmlDocumentSignature(signedXmlDocument));
		}

		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2012_512_Certificates))]
		public void ShouldSignXmlWithGost_R3410_2012_512(TestCertificateInfo testCase)
		{
			// Given
			var certificate = testCase.Certificate;
			var keyContainer = certificate.GetPrivateKeyInfo();
			var signingKey = new Gost_R3410_2012_512_AsymmetricAlgorithm(keyContainer);
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
			var signedXml = new GostSignedXml(signingKey.ProviderType, xmlDocument);

			// Установка ключа для создания подписи
			signedXml.SigningKey = signingKey;

			// Ссылка на узел, который нужно подписать, с указанием алгоритма хэширования
			var dataReference = new Reference { Uri = "#Id1", DigestMethod = GetDigestMethod(signingKey) };

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

		private static string GetDigestMethod(GostAsymmetricAlgorithm signingKey)
		{
			// Имя алгоритма вычисляем динамически, чтобы сделать код теста универсальным

			using (var hashAlgorithm = signingKey.CreateHashAlgorithm())
			{
				return hashAlgorithm.AlgorithmName;
			}
		}
	}
}