using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Gost_R3410;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Encrypt
{
	/// <summary>
	/// Шифрация и дешифрация XML с использованием контейнера ключей.
	/// </summary>
	/// <remarks>
	/// Тест имитирует обмен данными между условным отправителем, который шифрует заданный XML-документ, и условным получателем, который дешифрует
	/// зашифрованный XML-документ. Шифрация и дешифрация осуществляется без использования сертификатов. Шифрация осуществляется с использованием
	/// случайного симметричного ключа, который в свою очередь шифруется с использованием открытого ключа получателя. Соответственно для дешифрации
	/// данных сначала расшифровывается случайный симметричный ключ с использованием закрытого ключа получателя.
	/// 
	/// Перед началом теста имитируется передача получателем своего открытого ключа отправителю. Для этого получатель извлекает информацию о закрытом
	/// ключе из контейнера ключей, формирует закрытый ключ для дешифрации XML и условно передает (экспортирует) отправителю информацию о своем открытом
	/// ключе. Отправитель в свою очередь принимает (импортирует) от получателя информацию о его открытом ключе и формирует открытый ключ для шифрации XML.
	/// 
	/// Тест создает XML-документ, выборочно шифрует элементы данного документа с использованием случайного симметричного ключа, а затем дешифрует
	/// полученный зашифрованный документ. Случайный симметричного ключ в свою очередь шифруется открытым асимметричным ключом получателя и в зашифрованном
	/// виде добавляется в зашифрованный документ.
	/// </remarks>
	[TestFixture(Description = "Шифрация и дешифрация XML с использованием контейнера ключей")]
	public class EncryptedXmlKeyContainerTest
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2001_Certificates))]
		public void ShouldEncryptXmlWithGost_R3410_2001(TestCertificateInfo testCase)
		{
			// Given

			var certificate = testCase.Certificate;

			// Получатель экспортирует отправителю информацию о своем открытом ключе
			var keyContainer = certificate.GetPrivateKeyInfo();
			var privateKey = new Gost_R3410_2001_AsymmetricAlgorithm(keyContainer);
			var publicKeyInfo = privateKey.ExportParameters(false);

			// Отправитель импортирует от получателя информацию о его открытом ключе
			var publicKey = new Gost_R3410_2001_AsymmetricAlgorithm();
			publicKey.ImportParameters(publicKeyInfo);

			var xmlDocument = CreateXmlDocument();
			var expectedXml = xmlDocument.OuterXml;

			// When
			var encryptedXmlDocument = EncryptXmlDocument(xmlDocument, publicKey);
			var decryptedXmlDocument = DecryptXmlDocument(encryptedXmlDocument, privateKey);
			var actualXml = decryptedXmlDocument.OuterXml;

			// Then
			Assert.AreEqual(expectedXml, actualXml);
		}

		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2012_256_Certificates))]
		public void ShouldEncryptXmlWithGost_R3410_2012_256(TestCertificateInfo testCase)
		{
			// Given

			var certificate = testCase.Certificate;

			// Получатель экспортирует отправителю информацию о своем открытом ключе
			var keyContainer = certificate.GetPrivateKeyInfo();
			var privateKey = new Gost_R3410_2012_256_AsymmetricAlgorithm(keyContainer);
			var publicKeyInfo = privateKey.ExportParameters(false);

			// Отправитель импортирует от получателя информацию о его открытом ключе
			var publicKey = new Gost_R3410_2012_256_AsymmetricAlgorithm();
			publicKey.ImportParameters(publicKeyInfo);

			var xmlDocument = CreateXmlDocument();
			var expectedXml = xmlDocument.OuterXml;

			// When
			var encryptedXmlDocument = EncryptXmlDocument(xmlDocument, publicKey);
			var decryptedXmlDocument = DecryptXmlDocument(encryptedXmlDocument, privateKey);
			var actualXml = decryptedXmlDocument.OuterXml;

			// Then
			Assert.AreEqual(expectedXml, actualXml);
		}

		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Gost_R3410_2012_512_Certificates))]
		public void ShouldEncryptXmlWithGost_R3410_2012_512(TestCertificateInfo testCase)
		{
			// Given

			var certificate = testCase.Certificate;

			// Получатель экспортирует отправителю информацию о своем открытом ключе
			var keyContainer = certificate.GetPrivateKeyInfo();
			var privateKey = new Gost_R3410_2012_512_AsymmetricAlgorithm(keyContainer);
			var publicKeyInfo = privateKey.ExportParameters(false);

			// Отправитель импортирует от получателя информацию о его открытом ключе
			var publicKey = new Gost_R3410_2012_512_AsymmetricAlgorithm();
			publicKey.ImportParameters(publicKeyInfo);

			var xmlDocument = CreateXmlDocument();
			var expectedXml = xmlDocument.OuterXml;

			// When
			var encryptedXmlDocument = EncryptXmlDocument(xmlDocument, publicKey);
			var decryptedXmlDocument = DecryptXmlDocument(encryptedXmlDocument, privateKey);
			var actualXml = decryptedXmlDocument.OuterXml;

			// Then
			Assert.AreEqual(expectedXml, actualXml);
		}

		private static XmlDocument CreateXmlDocument()
		{
			var document = new XmlDocument();
			document.LoadXml(Resources.EncryptedXmlExample);
			return document;
		}

		private static XmlDocument EncryptXmlDocument(XmlDocument xmlDocument, GostAsymmetricAlgorithm publicKey)
		{
			// Создание объекта для шифрации XML
			var encryptedXml = new GostEncryptedXml(publicKey.ProviderType);

			// Поиск элементов для шифрации
			var elements = xmlDocument.SelectNodes("//SomeElement[@Encrypt='true']");

			if (elements != null)
			{
				var elementIndex = 0;

				foreach (XmlElement element in elements)
				{
					// Создание случайного сессионного ключа
					using (var sessionKey = new Gost_28147_89_SymmetricAlgorithm(publicKey.ProviderType))
					{
						// Шифрация элемента
						var encryptedData = encryptedXml.EncryptData(element, sessionKey, false);

						// Шифрация сессионного ключа с использованием публичного асимметричного ключа
						var encryptedSessionKeyData = GostEncryptedXml.EncryptKey(sessionKey, publicKey);

						// Формирование элемента EncryptedData
						var elementEncryptedData = new EncryptedData();
						elementEncryptedData.Id = "EncryptedElement" + elementIndex++;
						elementEncryptedData.Type = EncryptedXml.XmlEncElementUrl;
						elementEncryptedData.EncryptionMethod = new EncryptionMethod(sessionKey.AlgorithmName);
						elementEncryptedData.CipherData.CipherValue = encryptedData;
						elementEncryptedData.KeyInfo = new KeyInfo();

						// Формирование информации о зашифрованном сессионном ключе
						var encryptedSessionKey = new EncryptedKey();
						encryptedSessionKey.CipherData = new CipherData(encryptedSessionKeyData);
						encryptedSessionKey.EncryptionMethod = new EncryptionMethod(publicKey.KeyExchangeAlgorithm);
						encryptedSessionKey.AddReference(new DataReference { Uri = "#" + elementEncryptedData.Id });
						encryptedSessionKey.KeyInfo.AddClause(new KeyInfoName { Value = "KeyName1" });

						// Добавление ссылки на зашифрованный ключ, используемый при шифровании данных
						elementEncryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedSessionKey));

						// Замена элемента его зашифрованным представлением
						GostEncryptedXml.ReplaceElement(element, elementEncryptedData, false);
					}
				}
			}

			return xmlDocument;
		}

		private static XmlDocument DecryptXmlDocument(XmlDocument encryptedXmlDocument, GostAsymmetricAlgorithm privateKey)
		{
			// Создание объекта для дешифрации XML
			var encryptedXml = new GostEncryptedXml(privateKey.ProviderType, encryptedXmlDocument);

			// Добавление ссылки на приватный асимметричный ключ
			encryptedXml.AddKeyNameMapping("KeyName1", privateKey);

			// Расшифровка зашифрованных элементов документа
			encryptedXml.DecryptDocument();

			return encryptedXmlDocument;
		}
	}
}