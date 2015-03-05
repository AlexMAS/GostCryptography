using System.Collections;
using System.Reflection;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Cryptography;
using GostCryptography.Properties;

namespace GostCryptography.Xml
{
	sealed class GostSignedXmlImpl : SignedXml
	{
		public GostSignedXmlImpl()
		{
		}

		public GostSignedXmlImpl(XmlElement element)
			: base(element)
		{
		}

		public GostSignedXmlImpl(XmlDocument document)
			: base(document)
		{
		}


		public GetIdElementDelegate GetIdElementHandler { get; set; }


		[SecuritySafeCritical]
		public void ComputeSignatureGost()
		{
			var signingKey = SigningKey;

			if (signingKey == null)
			{
				ComputeSignatureBase();
			}
			else
			{
				if ((SignedInfo.SignatureMethod == null) && (signingKey is Gost3410AsymmetricAlgorithmBase))
				{
					SignedInfo.SignatureMethod = signingKey.SignatureAlgorithm;
				}

				ComputeSignatureBase();
			}
		}

		[SecurityCritical]
		private void ComputeSignatureBase()
		{
			ComputeSignature();
		}


		protected override AsymmetricAlgorithm GetPublicKey()
		{
			if (KeyInfo == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.XmlKeyInfoRequired);
			}

			if (X509Enumumerable != null)
			{
				var nextCertificatePublicKey = GetNextCertificatePublicKey();

				if (nextCertificatePublicKey != null)
				{
					return nextCertificatePublicKey;
				}
			}

			if (KeyInfoEnumerable == null)
			{
				KeyInfoEnumerable = KeyInfo.GetEnumerator();
			}

			var keyInfoEnum = KeyInfoEnumerable;

			while (keyInfoEnum.MoveNext())
			{
				var rsaKeyValue = keyInfoEnum.Current as RSAKeyValue;

				if (rsaKeyValue != null)
				{
					return rsaKeyValue.Key;
				}

				var dsaKeyValue = keyInfoEnum.Current as DSAKeyValue;

				if (dsaKeyValue != null)
				{
					return dsaKeyValue.Key;
				}

				var gostKeyValue = keyInfoEnum.Current as GostKeyValue;

				if (gostKeyValue != null)
				{
					return gostKeyValue.Key;
				}

				var keyInfoX509Data = keyInfoEnum.Current as KeyInfoX509Data;

				if (keyInfoX509Data != null)
				{
					X509Collection = GostXmlUtils.BuildBagOfCertsVerification(keyInfoX509Data);

					if (X509Collection.Count > 0)
					{
						X509Enumumerable = X509Collection.GetEnumerator();

						var nextCertificatePublicKey = GetNextCertificatePublicKey();

						if (nextCertificatePublicKey != null)
						{
							return nextCertificatePublicKey;
						}
					}
				}
			}

			return null;
		}

		[SecuritySafeCritical]
		private AsymmetricAlgorithm GetNextCertificatePublicKey()
		{
			while (X509Enumumerable.MoveNext())
			{
				var certificate = X509Enumumerable.Current as X509Certificate2;

				if (certificate != null)
				{
					return certificate.GetPublicKeyAlgorithm();
				}
			}

			return null;
		}

		public override XmlElement GetIdElement(XmlDocument document, string idValue)
		{
			if (GetIdElementHandler != null)
			{
				return GetIdElementHandler(document, idValue);
			}

			return base.GetIdElement(document, idValue);
		}


		// KeyInfoEnumerable

		private static volatile FieldInfo _keyInfoEnumerableField;
		private static readonly object KeyInfoEnumerableFieldSync = new object();

		private static FieldInfo KeyInfoEnumerableField
		{
			get
			{
				if (_keyInfoEnumerableField == null)
				{
					lock (KeyInfoEnumerableFieldSync)
					{
						if (_keyInfoEnumerableField == null)
						{
							_keyInfoEnumerableField = typeof(SignedXml).GetField("m_keyInfoEnum", BindingFlags.Instance | BindingFlags.NonPublic);
						}
					}
				}

				if (_keyInfoEnumerableField == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "m_keyInfoEnum");
				}

				return _keyInfoEnumerableField;
			}
		}

		private IEnumerator KeyInfoEnumerable
		{
			get { return (IEnumerator)KeyInfoEnumerableField.GetValue(this); }
			set { KeyInfoEnumerableField.SetValue(this, value); }
		}


		// X509Enumumerable

		private static volatile FieldInfo _x509EnumumerableField;
		private static readonly object X509EnumumerableSync = new object();

		private static FieldInfo X509EnumumerableField
		{
			get
			{
				if (_x509EnumumerableField == null)
				{
					lock (X509EnumumerableSync)
					{
						if (_x509EnumumerableField == null)
						{
							_x509EnumumerableField = typeof(SignedXml).GetField("m_x509Enum", BindingFlags.Instance | BindingFlags.NonPublic);
						}
					}
				}

				if (_x509EnumumerableField == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "m_x509Enum");
				}

				return _x509EnumumerableField;
			}
		}

		private IEnumerator X509Enumumerable
		{
			get { return (IEnumerator)X509EnumumerableField.GetValue(this); }
			set { X509EnumumerableField.SetValue(this, value); }
		}


		// X509Collection

		private static volatile FieldInfo _x509CollectionField;
		private static readonly object X509CollectionFieldSync = new object();

		private static FieldInfo X509CollectionField
		{
			get
			{
				if (_x509CollectionField == null)
				{
					lock (X509CollectionFieldSync)
					{
						if (_x509CollectionField == null)
						{
							_x509CollectionField = typeof(SignedXml).GetField("m_x509Collection", BindingFlags.Instance | BindingFlags.NonPublic);
						}
					}
				}

				if (_keyInfoEnumerableField == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "m_x509Collection");
				}

				return _x509CollectionField;
			}
		}

		private X509Certificate2Collection X509Collection
		{
			get { return (X509Certificate2Collection)X509CollectionField.GetValue(this); }
			set { X509CollectionField.SetValue(this, value); }
		}
	}
}