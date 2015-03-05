using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Cryptography;
using GostCryptography.Tests.Properties;
using GostCryptography.Xml;

using NUnit.Framework;

namespace GostCryptography.Tests.Xml.Encrypt
{
	/// <summary>
	/// Шифрация и дешифрация XML с использованием общего симметричного ключа.
	/// </summary>
	/// <remarks>
	/// Тест создает XML-документ, выборочно шифрует элементы данного документа с использованием общего симметричного ключа,
	/// а затем дешифрует полученный зашифрованный документ.
	/// </remarks>
	[TestFixture(Description = "Шифрация и дешифрация XML с использованием общего симметричного ключа")]
	public sealed class EncryptedXmlSharedKeyTest
	{
		private Gost28147SymmetricAlgorithm _sharedKey;

		[SetUp]
		public void SetUp()
		{
			_sharedKey = new Gost28147SymmetricAlgorithm();
		}

		[TearDown]
		public void TearDown()
		{
			try
			{
				_sharedKey.Dispose();
			}
			finally
			{
				_sharedKey = null;
			}
		}

		[Test]
		public void EncryptXml()
		{
			// Given
			var sharedKey = _sharedKey;
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

		private static XmlDocument EncryptXmlDocument(XmlDocument xmlDocument, SymmetricAlgorithm sharedKey)
		{
			// Создание объекта для шифрации XML
			var encryptedXml = new GostEncryptedXml();

			// Поиск элементов для шифрации
			var elements = xmlDocument.SelectNodes("//SomeElement[@Encrypt='true']");

			if (elements != null)
			{
				foreach (XmlElement element in elements)
				{
					// Шифрация элемента
					var encryptedData = encryptedXml.EncryptData(element, sharedKey, false);

					// Формирование элемента EncryptedData
					var elementEncryptedData = new EncryptedData();
					elementEncryptedData.Type = EncryptedXml.XmlEncElementUrl;
					elementEncryptedData.EncryptionMethod = new EncryptionMethod(GostEncryptedXml.XmlEncGost28147Url);
					elementEncryptedData.CipherData.CipherValue = encryptedData;

					// Замена элемента его зашифрованным представлением
					GostEncryptedXml.ReplaceElement(element, elementEncryptedData, false);
				}
			}

			return xmlDocument;
		}

		private static XmlDocument DecryptXmlDocument(XmlDocument encryptedXmlDocument, SymmetricAlgorithm sharedKey)
		{
			// Создание объекта для дешифрации XML
			var encryptedXml = new GostEncryptedXml(encryptedXmlDocument);

			var nsManager = new XmlNamespaceManager(encryptedXmlDocument.NameTable);
			nsManager.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);

			// Поиск всех зашифрованных XML-элементов
			var encryptedDataList = encryptedXmlDocument.SelectNodes("//enc:EncryptedData", nsManager);

			if (encryptedDataList != null)
			{
				foreach (XmlElement encryptedData in encryptedDataList)
				{
					// Загрузка элемента EncryptedData
					var elementEncryptedData = new EncryptedData();
					elementEncryptedData.LoadXml(encryptedData);

					// Расшифровка элемента EncryptedData
					var decryptedData = encryptedXml.DecryptData(elementEncryptedData, sharedKey);

					// Замена элемента EncryptedData его расшифрованным представлением
					encryptedXml.ReplaceData(encryptedData, decryptedData);
				}
			}

			return encryptedXmlDocument;
		}
	}
}