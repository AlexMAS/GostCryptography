using System.Collections;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Xml;

using GostCryptography.Properties;

namespace GostCryptography.Reflection
{
	static class EncryptedXmlHelper
	{
		private static readonly object DocumentFieldSync = new object();
		private static volatile FieldInfo _documentField;

		public static XmlDocument GetDocument(this EncryptedXml encryptedXml)
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

			return (XmlDocument)_documentField.GetValue(encryptedXml);
		}


		private static readonly object KeyNameMappingFieldSync = new object();
		private static volatile FieldInfo _keyNameMappingField;

		public static Hashtable GetKeyNameMapping(this EncryptedXml encryptedXml)
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

			return (Hashtable)_keyNameMappingField.GetValue(encryptedXml);
		}


		private static readonly object GetCipherValueMethodSync = new object();
		private static volatile MethodInfo _getCipherValueMethod;

		public static byte[] GetCipherValue(this EncryptedXml encryptedXml, CipherData cipherData)
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

			return (byte[])_getCipherValueMethod.Invoke(encryptedXml, new object[] { cipherData });
		}
	}
}