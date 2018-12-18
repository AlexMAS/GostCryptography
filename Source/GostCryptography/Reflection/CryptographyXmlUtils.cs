using System;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

using GostCryptography.Properties;

namespace GostCryptography.Reflection
{
	static class CryptographyXmlUtils
	{
		public static X509Certificate2Collection BuildBagOfCertsVerification(KeyInfoX509Data keyInfoX509Data)
		{
			return BuildBagOfCerts(keyInfoX509Data, 0);
		}

		public static X509Certificate2Collection BuildBagOfCertsDecryption(KeyInfoX509Data keyInfoX509Data)
		{
			return BuildBagOfCerts(keyInfoX509Data, 1);
		}

		private static X509Certificate2Collection BuildBagOfCerts(KeyInfoX509Data keyInfoX509Data, int certUsageType)
		{
			try
			{
				return (X509Certificate2Collection)BuildBagOfCertsMethod.Invoke(null, new object[] { keyInfoX509Data, certUsageType });
			}
			catch (TargetInvocationException exception)
			{
				if (exception.InnerException != null)
				{
					throw exception.InnerException;
				}

				throw;
			}
		}

		private static volatile MethodInfo _buildBagOfCertsMethod;
		private static readonly object BuildBagOfCertsMethodSync = new object();

		private static MethodInfo BuildBagOfCertsMethod
		{
			get
			{
				if (_buildBagOfCertsMethod == null)
				{
					lock (BuildBagOfCertsMethodSync)
					{
						if (_buildBagOfCertsMethod == null)
						{
							_buildBagOfCertsMethod = CryptographyXmlUtilsType.GetMethod("BuildBagOfCerts", BindingFlags.Static | BindingFlags.NonPublic);
						}
					}
				}

				if (_buildBagOfCertsMethod == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, $"{CryptographyXmlUtilsType.FullName}.BuildBagOfCerts()");
				}

				return _buildBagOfCertsMethod;
			}
		}


		public static string ExtractIdFromLocalUri(string uri)
		{
			try
			{
				return (string)ExtractIdFromLocalUriMethod.Invoke(null, new object[] { uri });
			}
			catch (TargetInvocationException exception)
			{
				if (exception.InnerException != null)
				{
					throw exception.InnerException;
				}

				throw;
			}
		}

		private static volatile MethodInfo _extractIdFromLocalUriMethod;
		private static readonly object ExtractIdFromLocalUriMethodSync = new object();

		private static MethodInfo ExtractIdFromLocalUriMethod
		{
			get
			{
				if (_extractIdFromLocalUriMethod == null)
				{
					lock (ExtractIdFromLocalUriMethodSync)
					{
						if (_extractIdFromLocalUriMethod == null)
						{
							_extractIdFromLocalUriMethod = CryptographyXmlUtilsType.GetMethod("ExtractIdFromLocalUri", BindingFlags.Static | BindingFlags.NonPublic);
						}
					}
				}

				if (_extractIdFromLocalUriMethod == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, $"{CryptographyXmlUtilsType.FullName}.ExtractIdFromLocalUri()");
				}

				return _extractIdFromLocalUriMethod;
			}
		}


		private static volatile Type _cryptographyXmlUtilsType;
		private static readonly object CryptographyXmlUtilsTypeSync = new object();

		private static Type CryptographyXmlUtilsType
		{
			get
			{
				if (_cryptographyXmlUtilsType == null)
				{
					lock (CryptographyXmlUtilsTypeSync)
					{
						if (_cryptographyXmlUtilsType == null)
						{
							_cryptographyXmlUtilsType = typeof(SignedXml).Assembly.GetType("System.Security.Cryptography.Xml.Utils");
						}
					}
				}

				if (_cryptographyXmlUtilsType == null)
				{
					throw ExceptionUtility.CryptographicException(Resources.XmlCannotFindPrivateMember, "System.Security.Cryptography.Xml.Utils");
				}

				return _cryptographyXmlUtilsType;
			}
		}
	}
}