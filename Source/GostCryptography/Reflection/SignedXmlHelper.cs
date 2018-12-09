using System.Collections;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

using GostCryptography.Properties;

namespace GostCryptography.Reflection
{
	static class SignedXmlHelper
	{
		public static IEnumerator GetKeyInfoEnumerable(this SignedXml signedXml)
		{
			return (IEnumerator)KeyInfoEnumerableField.GetValue(signedXml);
		}

		public static void SetKeyInfoEnumerable(this SignedXml signedXml, IEnumerator keyInfoEnumerable)
		{
			KeyInfoEnumerableField.SetValue(signedXml, keyInfoEnumerable);
		}

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


		public static IEnumerator GetX509Enumerable(this SignedXml signedXml)
		{
			return (IEnumerator)X509EnumerableField.GetValue(signedXml);
		}

		public static void SetX509Enumerable(this SignedXml signedXml, IEnumerator x509Enumerable)
		{
			X509EnumerableField.SetValue(signedXml, x509Enumerable);
		}

		private static volatile FieldInfo _x509EnumerableField;
		private static readonly object X509EnumerableSync = new object();

		private static FieldInfo X509EnumerableField
		{
			get
			{
				if (_x509EnumerableField == null)
				{
					lock (X509EnumerableSync)
					{
						if (_x509EnumerableField == null)
						{
							_x509EnumerableField = typeof(SignedXml).GetField("m_x509Enum", BindingFlags.Instance | BindingFlags.NonPublic);
						}
					}
				}

				if (_x509EnumerableField == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "m_x509Enum");
				}

				return _x509EnumerableField;
			}
		}


		public static X509Certificate2Collection GetX509Collection(this SignedXml signedXml)
		{
			return (X509Certificate2Collection)X509CollectionField.GetValue(signedXml);
		}

		public static void SetX509Collection(this SignedXml signedXml, X509Certificate2Collection x509Collection)
		{
			X509CollectionField.SetValue(signedXml, x509Collection);
		}

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
	}
}