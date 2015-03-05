using System;
using System.Collections;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Policy;
using System.Xml;

using GostCryptography.Cryptography;
using GostCryptography.Properties;

namespace GostCryptography.Xml
{
	sealed class GostEncryptedXmlImpl : EncryptedXml
	{
		public GostEncryptedXmlImpl()
		{
		}

		public GostEncryptedXmlImpl(XmlDocument document)
			: base(document)
		{
		}

		public GostEncryptedXmlImpl(XmlDocument document, Evidence evidence)
			: base(document, evidence)
		{
		}


		public new void AddKeyNameMapping(string keyName, object keyObject)
		{
			if (string.IsNullOrEmpty(keyName))
			{
				throw ExceptionUtility.ArgumentNull("keyName");
			}

			if (keyObject == null)
			{
				throw ExceptionUtility.ArgumentNull("keyObject");
			}

			if (keyObject is Gost3410AsymmetricAlgorithmBase)
			{
				KeyNameMapping.Add(keyName, keyObject);
			}
			else
			{
				base.AddKeyNameMapping(keyName, keyObject);
			}
		}


		[SecuritySafeCritical]
		public new EncryptedData Encrypt(XmlElement element, X509Certificate2 certificate)
		{
			if (element == null)
			{
				return base.Encrypt(element, certificate);
			}

			if (certificate == null)
			{
				return base.Encrypt(element, certificate);
			}

			if (!string.Equals(certificate.PublicKey.Oid.Value, GostCryptoConfig.DefaultSignOid, StringComparison.OrdinalIgnoreCase))
			{
				return base.Encrypt(element, certificate);
			}

			var encryptedKey = new EncryptedKey
							   {
								   EncryptionMethod = new EncryptionMethod(GostEncryptedXml.XmlEncGostKeyTransportUrl)
							   };

			encryptedKey.KeyInfo.AddClause(new KeyInfoX509Data(certificate));

			var encriptionKey = new Gost28147SymmetricAlgorithm();
			var publicKey = certificate.GetPublicKeyAlgorithm();
			encryptedKey.CipherData.CipherValue = EncryptKey(encriptionKey, publicKey as Gost3410AsymmetricAlgorithmBase);

			var encryptedData = new EncryptedData
								{
									Type = XmlEncElementUrl,
									EncryptionMethod = new EncryptionMethod(GostEncryptedXml.XmlEncGost28147Url)
								};

			encryptedData.KeyInfo.AddClause(new KeyInfoEncryptedKey(encryptedKey));
			encryptedData.CipherData.CipherValue = EncryptData(element, encriptionKey, false);

			return encryptedData;
		}

		public static byte[] EncryptKey(Gost28147SymmetricAlgorithmBase sessionKey, Gost3410AsymmetricAlgorithmBase publicKey)
		{
			if (sessionKey == null)
			{
				throw ExceptionUtility.ArgumentNull("sessionKey");
			}

			if (publicKey == null)
			{
				throw ExceptionUtility.ArgumentNull("publicKey");
			}

			var formatter = new GostKeyExchangeFormatter(publicKey);
			return formatter.CreateKeyExchangeData(sessionKey);
		}

		public static byte[] EncryptKey(Gost28147SymmetricAlgorithmBase sessionKey, Gost28147SymmetricAlgorithmBase sharedKey, GostKeyExchangeExportMethod exportMethod)
		{
			if (sessionKey == null)
			{
				throw ExceptionUtility.ArgumentNull("sessionKey");
			}

			if (sharedKey == null)
			{
				throw ExceptionUtility.ArgumentNull("sharedKey");
			}

			return sharedKey.EncodePrivateKey(sessionKey, exportMethod);
		}


		public override byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			if (encryptedData == null)
			{
				throw ExceptionUtility.ArgumentNull("encryptedData");
			}

			if (symmetricAlgorithmUri == null)
			{
				if (encryptedData.EncryptionMethod == null)
				{
					return base.GetDecryptionIV(encryptedData, null);
				}

				symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
			}

			if (string.Equals(symmetricAlgorithmUri, GostEncryptedXml.XmlEncGost28147Url, StringComparison.OrdinalIgnoreCase))
			{
				var iv = new byte[8];
				Buffer.BlockCopy(GetCipherValue(encryptedData.CipherData), 0, iv, 0, iv.Length);

				return iv;
			}

			return base.GetDecryptionIV(encryptedData, symmetricAlgorithmUri);
		}

		public override SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri)
		{
			if (encryptedData == null)
			{
				throw ExceptionUtility.ArgumentNull("encryptedData");
			}

			SymmetricAlgorithm decryptionKey = null;

			if (encryptedData.KeyInfo != null)
			{
				EncryptedKey encryptedKey = null;

				foreach (var keyInfo in encryptedData.KeyInfo)
				{
					// Извлечение ключа по имени
					if (keyInfo is KeyInfoName)
					{
						var keyName = ((KeyInfoName)keyInfo).Value;
						var keyAlgorithm = KeyNameMapping[keyName];

						if (keyAlgorithm == null)
						{
							var nsManager = new XmlNamespaceManager(Document.NameTable);
							nsManager.AddNamespace("enc", XmlEncNamespaceUrl);

							var encryptedKeyNodes = Document.SelectNodes("//enc:EncryptedKey", nsManager);

							if (encryptedKeyNodes != null)
							{
								foreach (XmlElement encryptedKeyNode in encryptedKeyNodes)
								{
									var currentEncryptedKey = new EncryptedKey();
									currentEncryptedKey.LoadXml(encryptedKeyNode);

									if ((currentEncryptedKey.CarriedKeyName == keyName) && (currentEncryptedKey.Recipient == Recipient))
									{
										encryptedKey = currentEncryptedKey;
										break;
									}
								}
							}
						}
						else
						{
							decryptionKey = (SymmetricAlgorithm)keyAlgorithm;
						}

						break;
					}

					// Извлечение ключа по ссылке
					if (keyInfo is KeyInfoRetrievalMethod)
					{
						var idValue = GostXmlUtils.ExtractIdFromLocalUri(((KeyInfoRetrievalMethod)keyInfo).Uri);
						var idElement = GetIdElement(Document, idValue);

						if (idElement != null)
						{
							encryptedKey = new EncryptedKey();
							encryptedKey.LoadXml(idElement);
						}

						break;
					}

					// Ключ в готовом виде
					if (keyInfo is KeyInfoEncryptedKey)
					{
						encryptedKey = ((KeyInfoEncryptedKey)keyInfo).EncryptedKey;
						break;
					}
				}

				if (decryptionKey == null && encryptedKey != null)
				{
					if (symmetricAlgorithmUri == null)
					{
						if (encryptedData.EncryptionMethod == null)
						{
							throw ExceptionUtility.CryptographicException(Resources.XmlMissingAlgorithm);
						}

						symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
					}

					decryptionKey = DecryptEncryptedKeyClass(encryptedKey, symmetricAlgorithmUri);
				}
			}

			return decryptionKey;
		}

		[SecuritySafeCritical]
		private SymmetricAlgorithm DecryptEncryptedKeyClass(EncryptedKey encryptedKey, string symmetricAlgorithmUri)
		{
			if (encryptedKey == null)
			{
				throw ExceptionUtility.ArgumentNull("encryptedKey");
			}

			SymmetricAlgorithm decryptionKey = null;

			if (encryptedKey.KeyInfo != null)
			{
				foreach (var keyInfo in encryptedKey.KeyInfo)
				{
					// Извлечение ключа по имени
					if (keyInfo is KeyInfoName)
					{
						var keyName = ((KeyInfoName)keyInfo).Value;
						var keyAlgorithm = KeyNameMapping[keyName];

						if (keyAlgorithm != null)
						{
							if (keyAlgorithm is SymmetricAlgorithm)
							{
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (SymmetricAlgorithm)keyAlgorithm, symmetricAlgorithmUri, encryptedKey.EncryptionMethod.KeyAlgorithm);
							}
							else if (keyAlgorithm is RSA)
							{
								var useOaep = (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl);
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (RSA)keyAlgorithm, useOaep, symmetricAlgorithmUri);
							}
							else if (keyAlgorithm is Gost3410AsymmetricAlgorithmBase)
							{
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (Gost3410AsymmetricAlgorithmBase)keyAlgorithm);
							}
						}

						break;
					}

					// Извлечение ключа из сертификата
					if (keyInfo is KeyInfoX509Data)
					{
						var certificates = GostXmlUtils.BuildBagOfCertsDecryption((KeyInfoX509Data)keyInfo);

						foreach (var certificate in certificates)
						{
							var privateKey = certificate.GetPrivateKeyAlgorithm();

							if (privateKey is RSA)
							{
								var useOaep = (encryptedKey.EncryptionMethod != null) && (encryptedKey.EncryptionMethod.KeyAlgorithm == XmlEncRSAOAEPUrl);
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (RSA)privateKey, useOaep, symmetricAlgorithmUri);
							}
							else if (privateKey is Gost3410AsymmetricAlgorithmBase)
							{
								decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, (Gost3410AsymmetricAlgorithmBase)privateKey);
							}
						}

						break;
					}

					// Извлечение ключа по ссылке
					if (keyInfo is KeyInfoRetrievalMethod)
					{
						var idValue = GostXmlUtils.ExtractIdFromLocalUri(((KeyInfoRetrievalMethod)keyInfo).Uri);
						var idElement = GetIdElement(Document, idValue);

						if (idElement != null)
						{
							var secondEncryptedKey = new EncryptedKey();
							secondEncryptedKey.LoadXml(idElement);

							decryptionKey = DecryptEncryptedKeyClass(secondEncryptedKey, symmetricAlgorithmUri);
						}

						break;
					}

					// Ключ в готовом виде
					if (keyInfo is KeyInfoEncryptedKey)
					{
						var secondEncryptedKey = ((KeyInfoEncryptedKey)keyInfo).EncryptedKey;
						var symmetricAlgorithm = DecryptEncryptedKeyClass(secondEncryptedKey, symmetricAlgorithmUri);

						if (symmetricAlgorithm != null)
						{
							decryptionKey = DecryptKeyClass(encryptedKey.CipherData.CipherValue, symmetricAlgorithm, symmetricAlgorithmUri, encryptedKey.EncryptionMethod.KeyAlgorithm);
						}

						break;
					}
				}
			}

			return decryptionKey;
		}

		private static SymmetricAlgorithm DecryptKeyClass(byte[] keyData, SymmetricAlgorithm algorithm, string symmetricAlgorithmUri, string encryptionKeyAlgorithm)
		{
			if (keyData == null)
			{
				throw ExceptionUtility.ArgumentNull("keyData");
			}

			if (algorithm == null)
			{
				throw ExceptionUtility.ArgumentNull("algorithm");
			}

			SymmetricAlgorithm decryptionKey = null;

			var gost28147 = algorithm as Gost28147SymmetricAlgorithmBase;

			if (gost28147 != null)
			{
				if (string.Equals(encryptionKeyAlgorithm, GostEncryptedXml.XmlEncGostKeyExportUrl, StringComparison.OrdinalIgnoreCase))
				{
					decryptionKey = gost28147.DecodePrivateKey(keyData, GostKeyExchangeExportMethod.GostKeyExport);
				}

				if (string.Equals(encryptionKeyAlgorithm, GostEncryptedXml.XmlEncGostCryptoProKeyExportUrl, StringComparison.OrdinalIgnoreCase))
				{
					decryptionKey = gost28147.DecodePrivateKey(keyData, GostKeyExchangeExportMethod.CryptoProKeyExport);
				}
			}
			else
			{
				var decryptionKeyBytes = DecryptKey(keyData, algorithm);

				if (decryptionKeyBytes != null)
				{
					decryptionKey = (SymmetricAlgorithm)GostCryptoConfig.CreateFromName(symmetricAlgorithmUri);
					decryptionKey.Key = decryptionKeyBytes;
				}
			}

			if (decryptionKey == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.XmlMissingAlgorithm);
			}

			return decryptionKey;
		}

		private static SymmetricAlgorithm DecryptKeyClass(byte[] keyData, RSA algorithm, bool useOaep, string symmetricAlgorithmUri)
		{
			if (keyData == null)
			{
				throw ExceptionUtility.ArgumentNull("keyData");
			}

			if (algorithm == null)
			{
				throw ExceptionUtility.ArgumentNull("algorithm");
			}

			SymmetricAlgorithm decryptionKey = null;

			var decryptionKeyBytes = DecryptKey(keyData, algorithm, useOaep);

			if (decryptionKeyBytes != null)
			{
				decryptionKey = (SymmetricAlgorithm)GostCryptoConfig.CreateFromName(symmetricAlgorithmUri);
				decryptionKey.Key = decryptionKeyBytes;
			}

			if (decryptionKey == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.XmlMissingAlgorithm);
			}

			return decryptionKey;
		}

		public static SymmetricAlgorithm DecryptKeyClass(byte[] keyData, Gost3410AsymmetricAlgorithmBase privateKey)
		{
			if (keyData == null)
			{
				throw ExceptionUtility.ArgumentNull("keyData");
			}

			if (privateKey == null)
			{
				throw ExceptionUtility.ArgumentNull("privateKey");
			}

			var deformatter = new GostKeyExchangeDeformatter(privateKey);
			var decryptionKey = deformatter.DecryptKeyExchangeAlgorithm(keyData);

			return decryptionKey;
		}


		#region EncryptedXml Reflection

		// Document

		private static readonly object DocumentFieldSync = new object();
		private static volatile FieldInfo _documentField;

		private static FieldInfo DocumentField
		{
			get
			{
				if (_documentField == null)
				{
					lock (DocumentFieldSync)
					{
						if (_documentField == null)
						{
							_documentField = typeof(EncryptedXml).GetField("m_document", BindingFlags.Instance | BindingFlags.NonPublic);
						}
					}
				}

				if (_documentField == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "m_document");
				}

				return _documentField;
			}
		}

		private XmlDocument Document
		{
			get { return (XmlDocument)DocumentField.GetValue(this); }
		}


		// KeyNameMapping

		private static readonly object KeyNameMappingFieldSync = new object();
		private static volatile FieldInfo _keyNameMappingField;

		private static FieldInfo KeyNameMappingField
		{
			get
			{
				if (_keyNameMappingField == null)
				{
					lock (KeyNameMappingFieldSync)
					{
						if (_keyNameMappingField == null)
						{
							_keyNameMappingField = typeof(EncryptedXml).GetField("m_keyNameMapping", BindingFlags.Instance | BindingFlags.NonPublic);
						}
					}
				}

				if (_keyNameMappingField == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "m_keyNameMapping");
				}

				return _keyNameMappingField;
			}
		}

		private Hashtable KeyNameMapping
		{
			get { return (Hashtable)KeyNameMappingField.GetValue(this); }
		}


		// GetCipherValue()

		private static readonly object GetCipherValueMethodSync = new object();
		private static volatile MethodInfo _getCipherValueMethod;

		private static MethodInfo GetCipherValueMethod
		{
			get
			{
				if (_getCipherValueMethod == null)
				{
					lock (GetCipherValueMethodSync)
					{
						if (_getCipherValueMethod == null)
						{
							_getCipherValueMethod = typeof(EncryptedXml).GetMethod("GetCipherValue", BindingFlags.Instance | BindingFlags.NonPublic);
						}
					}
				}

				if (_getCipherValueMethod == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "GetCipherValue()");
				}

				return _getCipherValueMethod;
			}
		}

		private byte[] GetCipherValue(CipherData cipherData)
		{
			return (byte[])GetCipherValueMethod.Invoke(this, new object[] { cipherData });
		}

		#endregion
	}
}