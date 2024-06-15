using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Encrypt
{
	/// <summary>
	/// Шифрация и дешифрация XML с использованием случайного сессионного ключа.
	/// </summary>
	/// <remarks>
	/// Тест создает XML-документ, выборочно шифрует элементы данного документа с использованием случайного симметричного ключа,
	/// а затем дешифрует полученный зашифрованный документ. Случайный симметричного ключ в свою очередь шифруется общим симметричным
	/// ключом и в зашифрованном виде добавляется в зашифрованный документ.
	/// </remarks>
	[TestFixture(Description = "Шифрация и дешифрация XML с использованием случайного сессионного ключа")]
	public class EncryptedXmlSessionKey
	{
		[Test]
		[TestCaseSource(typeof(TestConfig), nameof(TestConfig.Providers))]
		public void ShouldEncryptXml(ProviderType providerType)
		{
			// Given
			var sharedKey = new Gost_28147_89_SymmetricAlgorithm(providerType);
			var xmlDocument = CreateXmlDocument();
			var expectedXml = xmlDocument.OuterXml;

			// When
			var encryptedXmlDocument = EncryptXmlDocument(xmlDocument, sharedKey);
			var decryptedXmlDocument = DecryptXmlDocument(encryptedXmlDocument, sharedKey);
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

		private static XmlDocument EncryptXmlDocument(XmlDocument xmlDocument, GostSymmetricAlgorithm sharedKey)
		{
			// Создание объекта для шифрации XML
			var encryptedXml = new GostEncryptedXml(sharedKey.ProviderType);

			// Поиск элементов для шифрации
			var elements = xmlDocument.SelectNodes("//SomeElement[@Encrypt='true']");

			if (elements != null)
			{
				var elementIndex = 0;

				foreach (XmlElement element in elements)
				{
					// Создание случайного сессионного ключа
					using (var sessionKey = new Gost_28147_89_SymmetricAlgorithm(sharedKey.ProviderType))
					{
						// Шифрация элемента
						var encryptedData = encryptedXml.EncryptData(element, sessionKey, false);

						// Шифрация сессионного ключа с использованием общего симметричного ключа
						var encryptedSessionKeyData = GostEncryptedXml.EncryptKey(sessionKey, sharedKey, GostKeyExchangeExportMethod.CryptoProKeyExport);

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
						encryptedSessionKey.EncryptionMethod = new EncryptionMethod(GostEncryptedXml.XmlEncGostCryptoProKeyExportUrl);
						encryptedSessionKey.AddReference(new DataReference { Uri = "#" + elementEncryptedData.Id });
						encryptedSessionKey.KeyInfo.AddClause(new KeyInfoName { Value = "SharedKey1" });

						// Добавление ссылки на зашифрованный ключ, используемый при шифровании данных
						elementEncryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedSessionKey));

						// Замена элемента его зашифрованным представлением
						GostEncryptedXml.ReplaceElement(element, elementEncryptedData, false);
					}
				}
			}

			return xmlDocument;
		}

		private static XmlDocument DecryptXmlDocument(XmlDocument encryptedXmlDocument, GostSymmetricAlgorithm sharedKey)
		{
			// Создание объекта для дешифрации XML
			var encryptedXml = new GostEncryptedXml(sharedKey.ProviderType, encryptedXmlDocument);

			// Добавление ссылки на общий симметричный ключ
			encryptedXml.AddKeyNameMapping("SharedKey1", sharedKey);

			// Расшифровка зашифрованных элементов документа
			encryptedXml.DecryptDocument();

			return encryptedXmlDocument;
		}
	}
}