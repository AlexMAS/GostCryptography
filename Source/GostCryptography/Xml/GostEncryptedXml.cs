using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Policy;
using System.Text;
using System.Xml;

using GostCryptography.Base;
using GostCryptography.Config;
using GostCryptography.Gost_28147_89;

namespace GostCryptography.Xml
{
	/// <summary>
	/// Объект для шифрации и дешифрации XML по ГОСТ 34.10.
	/// </summary>
	public sealed class GostEncryptedXml
	{
		/// <summary>
		/// URI пространства имен для синтаксиса и правил обработки при шифровании XML по ГОСТ.
		/// </summary>
		public const string XmlEncGostNamespaceUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:";

		/// <summary>
		/// URI алгоритма экспорта ключа по ГОСТ 28147-89.
		/// </summary>
		public const string XmlEncGostKeyExportUrl = XmlEncGostNamespaceUrl + "kw-gost";

		/// <summary>
		/// URI алгоритма экспорта ключа КриптоПро.
		/// </summary>
		public const string XmlEncGostCryptoProKeyExportUrl = XmlEncGostNamespaceUrl + "kw-cp";


		static GostEncryptedXml()
		{
			GostCryptoConfig.Initialize();
		}


		/// <inheritdoc cref="EncryptedXml()"/>
		public GostEncryptedXml() : this(GostCryptoConfig.ProviderType)
		{
		}

		/// <inheritdoc cref="EncryptedXml()"/>
		public GostEncryptedXml(ProviderType providerType)
		{
			_encryptedXml = new GostEncryptedXmlImpl(providerType);
		}

		/// <inheritdoc cref="EncryptedXml(XmlDocument)"/>
		public GostEncryptedXml(XmlDocument document) : this(GostCryptoConfig.ProviderType, document)
		{
		}

		/// <inheritdoc cref="EncryptedXml(XmlDocument)"/>
		public GostEncryptedXml(ProviderType providerType, XmlDocument document)
		{
			_encryptedXml = new GostEncryptedXmlImpl(providerType, document);
		}

		/// <inheritdoc cref="EncryptedXml(XmlDocument,Evidence)"/>
		public GostEncryptedXml(XmlDocument document, Evidence evidence) : this(GostCryptoConfig.ProviderType, document, evidence)
		{
		}

		/// <inheritdoc cref="EncryptedXml(XmlDocument,Evidence)"/>
		public GostEncryptedXml(ProviderType providerType, XmlDocument document, Evidence evidence)
		{
			_encryptedXml = new GostEncryptedXmlImpl(providerType, document, evidence);
		}


		private readonly GostEncryptedXmlImpl _encryptedXml;


		/// <inheritdoc cref="EncryptedXml.DocumentEvidence"/>
		public Evidence DocumentEvidence
		{
			get => _encryptedXml.DocumentEvidence;
			set => _encryptedXml.DocumentEvidence = value;
		}

		/// <inheritdoc cref="EncryptedXml.Resolver"/>
		public XmlResolver Resolver
		{
			get => _encryptedXml.Resolver;
			set => _encryptedXml.Resolver = value;
		}

		/// <inheritdoc cref="EncryptedXml.Padding"/>
		public PaddingMode Padding
		{
			get => _encryptedXml.Padding;
			set => _encryptedXml.Padding = value;
		}

		/// <inheritdoc cref="EncryptedXml.Mode"/>
		public CipherMode Mode
		{
			get => _encryptedXml.Mode;
			set => _encryptedXml.Mode = value;
		}

		/// <inheritdoc cref="EncryptedXml.Encoding"/>
		public Encoding Encoding
		{
			get => _encryptedXml.Encoding;
			set => _encryptedXml.Encoding = value;
		}

		/// <inheritdoc cref="EncryptedXml.Recipient"/>
		public string Recipient
		{
			get => _encryptedXml.Recipient;
			set => _encryptedXml.Recipient = value;
		}


		// Encryption

		/// <summary>
		/// Шифрует XML-элемент с помощью ключа с указанным именем.
		/// </summary>
		/// <param name="element">Шифруемый XML-элемент.</param>
		/// <param name="keyName">Имя ключа для шифрования XML-элемента.</param>
		/// <returns>Зашифрованное представление XML-элемента.</returns>
		public EncryptedData Encrypt(XmlElement element, string keyName)
		{
			return _encryptedXml.Encrypt(element, keyName);
		}

		/// <summary>
		/// Шифрует XML-элемент с помощью сертификата.
		/// </summary>
		/// <param name="element">Шифруемый XML-элемент.</param>
		/// <param name="certificate">Сертификат X.509 для шифрования XML-элемента.</param>
		/// <returns>Зашифрованное представление XML-элемента.</returns>
		public EncryptedData Encrypt(XmlElement element, X509Certificate2 certificate)
		{
			return _encryptedXml.Encrypt(element, certificate);
		}

		/// <summary>
		/// Шифрует данные с помощью указанного симметричного ключа.
		/// </summary>
		/// <param name="data">Шифруемые данные.</param>
		/// <param name="symmetricKey">Симметричный ключ для шифрования данных.</param>
		/// <returns>Массив байт, содержащий зашифрованные данные.</returns>
		public byte[] EncryptData(byte[] data, SymmetricAlgorithm symmetricKey)
		{
			return _encryptedXml.EncryptData(data, symmetricKey);
		}

		/// <summary>
		/// Шифрует XML-элемент с помощью указанного симметричного ключа.
		/// </summary>
		/// <param name="element">Шифруемый XML-элемент.</param>
		/// <param name="symmetricKey">Симметричный ключ для шифрования XML-элемента.</param>
		/// <param name="content">Значение true для шифрования только содержимого элемента; значение false для шифрования всего элемента.</param>
		/// <returns>Массив байт, содержащий зашифрованные данные.</returns>
		public byte[] EncryptData(XmlElement element, SymmetricAlgorithm symmetricKey, bool content)
		{
			return _encryptedXml.EncryptData(element, symmetricKey, content);
		}

		/// <summary>
		/// Шифрует сессионный ключ с помощью указанного общего симметричного ключа.
		/// </summary>
		/// <param name="keyData">Шифруемый сессионный ключ.</param>
		/// <param name="sharedKey">Общий симметричный ключ для шифрования сессионного ключа.</param>
		/// <returns>Массив байт, содержащий зашифрованный сессионный ключ.</returns>
		/// <remarks>Как правило сессионный ключ используется для шифрования данных и в свою очередь так же шифруется.</remarks>
		public static byte[] EncryptKey(byte[] keyData, SymmetricAlgorithm sharedKey)
		{
			return EncryptedXml.EncryptKey(keyData, sharedKey);
		}

		/// <summary>
		/// Шифрует сессионный ключ с помощью указанного асимметричного ключа RSA.
		/// </summary>
		/// <param name="keyData">Шифруемый сессионный ключ.</param>
		/// <param name="publicKey">Открытый ключ RSA для шифрования сессионного ключа.</param>
		/// <param name="useOaep">Значение, указывающее, следует ли использовать заполнение OAEP (Optimal Asymmetric Encryption Padding).</param>
		/// <returns>Массив байт, содержащий зашифрованный сессионный ключ.</returns>
		/// <remarks>Как правило сессионный ключ используется для шифрования данных и в свою очередь так же шифруется.</remarks>
		public static byte[] EncryptKey(byte[] keyData, RSA publicKey, bool useOaep)
		{
			return EncryptedXml.EncryptKey(keyData, publicKey, useOaep);
		}

		/// <summary>
		/// Шифрует сессионный ключ с помощью указанного асимметричного ключа ГОСТ Р 34.10.
		/// </summary>
		/// <param name="sessionKey">Шифруемый сессионный ключ.</param>
		/// <param name="publicKey">Открытый ключ ГОСТ Р 34.10 для шифрования сессионного ключа.</param>
		/// <returns>Массив байт, содержащий зашифрованный сессионный ключ.</returns>
		/// <remarks>Как правило сессионный ключ используется для шифрования данных и в свою очередь так же шифруется.</remarks>
		public static byte[] EncryptKey(Gost_28147_89_SymmetricAlgorithmBase sessionKey, GostAsymmetricAlgorithm publicKey)
		{
			return GostEncryptedXmlImpl.EncryptKey(sessionKey, publicKey);
		}

		/// <summary>
		/// Шифрует сессионный ключ с помощью указанного симметричного ключа ГОСТ 28147.
		/// </summary>
		/// <param name="sessionKey">Шифруемый сессионный ключ.</param>
		/// <param name="sharedKey">Общий симметричный ключ ГОСТ 28147 для шифрования сессионного ключа.</param>
		/// <param name="exportMethod">Алгоритм экспорта сессионного ключа.</param>
		/// <returns>Массив байт, содержащий зашифрованный сессионный ключ.</returns>
		/// <remarks>Как правило сессионный ключ используется для шифрования данных и в свою очередь так же шифруется.</remarks>
		public static byte[] EncryptKey(Gost_28147_89_SymmetricAlgorithmBase sessionKey, Gost_28147_89_SymmetricAlgorithmBase sharedKey, GostKeyExchangeExportMethod exportMethod = GostKeyExchangeExportMethod.GostKeyExport)
		{
			return GostEncryptedXmlImpl.EncryptKey(sessionKey, sharedKey, exportMethod);
		}


		/// <summary>
		/// Расшифровывает зашифрованный XML-элемент с помощью указанного симметричного ключа.
		/// </summary>
		/// <param name="encryptedData">Зашифрованное представление XML-элемента.</param>
		/// <param name="symmetricKey">Симметричный ключ для расшифровки данных.</param>
		/// <returns>Массив байт, содержащий расшифрованный XML-элемент.</returns>
		public byte[] DecryptData(EncryptedData encryptedData, SymmetricAlgorithm symmetricKey)
		{
			return _encryptedXml.DecryptData(encryptedData, symmetricKey);
		}

		/// <summary>
		/// Расшифровывает все зашифрованные XML-элементы документа.
		/// </summary>
		public void DecryptDocument()
		{
			_encryptedXml.DecryptDocument();
		}

		/// <summary>
		/// Возвращает вектор инициализации для расшифровки XML-элемента.
		/// </summary>
		/// <param name="encryptedData">Зашифрованное представление XML-элемента.</param>
		/// <param name="symmetricAlgorithmUri">URI алгоритма шифрования.</param>
		/// <returns>Массив байт, содержащий вектор инициализации для расшифровки XML-элемента.</returns>
		public byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			return _encryptedXml.GetDecryptionIV(encryptedData, symmetricAlgorithmUri);
		}

		/// <summary>
		/// Возвращает симметричный ключ для расшифровки XML-элемента.
		/// </summary>
		/// <param name="encryptedData">Зашифрованное представление XML-элемента.</param>
		/// <param name="symmetricAlgorithmUri">URI алгоритма шифрования.</param>
		/// <returns>Симметричный ключ для расшифровки XML-элемента.</returns>
		public SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			return _encryptedXml.GetDecryptionKey(encryptedData, symmetricAlgorithmUri);
		}

		/// <summary>
		/// Извлекает ключ из элемента &lt;EncryptedKey&gt;.
		/// </summary>
		/// <param name="encryptedKey">Элемент &lt;EncryptedKey&gt; с информацией о ключе шифрования.</param>
		/// <returns>Массив байт, содержащий ключ для расшифровки.</returns>
		public byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
		{
			return _encryptedXml.DecryptEncryptedKey(encryptedKey);
		}

		/// <summary>
		/// Расшифровывает сессионный ключ с помощью указанного общего симметричного ключа.
		/// </summary>
		/// <param name="keyData">Массив байт, содержащий зашифрованный сессионный ключ.</param>
		/// <param name="sharedKey">Общий симметричный ключ для расшифровки сессионного ключа.</param>
		/// <returns>Массив байт, который содержит сессионный ключ.</returns>
		/// <remarks>Как правило сессионный ключ используется для шифрования данных и в свою очередь так же шифруется.</remarks>
		public static byte[] DecryptKey(byte[] keyData, SymmetricAlgorithm sharedKey)
		{
			return EncryptedXml.EncryptKey(keyData, sharedKey);
		}

		/// <summary>
		/// Расшифровывает сессионный ключ с помощью указанного асимметричного ключа RSA.
		/// </summary>
		/// <param name="keyData">Массив байт, содержащий зашифрованный сессионный ключ.</param>
		/// <param name="privateKey">Закрытый ключ RSA для расшифровки сессионного ключа.</param>
		/// <param name="useOaep">Значение, указывающее, следует ли использовать заполнение OAEP (Optimal Asymmetric Encryption Padding).</param>
		/// <returns>Массив байт, который содержит сессионный ключ.</returns>
		/// <remarks>Как правило сессионный ключ используется для шифрования данных и в свою очередь так же шифруется.</remarks>
		public static byte[] DecryptKey(byte[] keyData, RSA privateKey, bool useOaep)
		{
			return EncryptedXml.DecryptKey(keyData, privateKey, useOaep);
		}

		/// <summary>
		/// Расшифровывает сессионный ключ с помощью указанного асимметричного ключа ГОСТ Р 34.10.
		/// </summary>
		/// <param name="keyData">Массив байт, содержащий зашифрованный сессионный ключ.</param>
		/// <param name="privateKey">Закрытый ключ ГОСТ Р 34.10 для расшифровки сессионного ключа.</param>
		/// <returns>Сессионный ключ.</returns>
		/// <remarks>Как правило сессионный ключ используется для шифрования данных и в свою очередь так же шифруется.</remarks>
		public static SymmetricAlgorithm DecryptKey(byte[] keyData, GostAsymmetricAlgorithm privateKey)
		{
			return GostEncryptedXmlImpl.DecryptKeyClass(keyData, privateKey);
		}


		/// <summary>
		/// Заменяет указанный зашифрованный XML-элемент его расшифрованным представлением.
		/// </summary>
		/// <param name="element">Заменяемый зашифрованный XML-элемент.</param>
		/// <param name="decryptedData">Расшифрованное представление XML-элемента.</param>
		public void ReplaceData(XmlElement element, byte[] decryptedData)
		{
			_encryptedXml.ReplaceData(element, decryptedData);
		}

		/// <summary>
		/// Заменяет указанный XML-элемент его зашифрованным представлением.
		/// </summary>
		/// <param name="element">Заменяемый XML-элемент.</param>
		/// <param name="encryptedData">Зашифрованное представление XML-элемента.</param>
		/// <param name="content">Значение true для замены только содержимого элемента; значение false для замены всего элемента.</param>
		public static void ReplaceElement(XmlElement element, EncryptedData encryptedData, bool content)
		{
			EncryptedXml.ReplaceElement(element, encryptedData, content);
		}

		/// <summary>
		/// Возвращает XML-элемент с указанным идентификатором.
		/// </summary>
		/// <param name="document">Документ для поиска идентификатора XML-элемента.</param>
		/// <param name="idValue">Значение идентификатора XML-элемента.</param>
		public XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			return _encryptedXml.GetIdElement(document, idValue);
		}

		/// <summary>
		/// Сопоставляет имя ключа шифрования со значением.
		/// </summary>
		/// <param name="keyName">Имя ключа шифрования.</param>
		/// <param name="keyObject">Значение ключа шифрования.</param>
		public void AddKeyNameMapping(string keyName, object keyObject)
		{
			_encryptedXml.AddKeyNameMapping(keyName, keyObject);
		}

		/// <summary>
		/// Сбрасывает все сопоставления между именами и ключами шифрования.
		/// </summary>
		public void ClearKeyNameMappings()
		{
			_encryptedXml.ClearKeyNameMappings();
		}
	}
}