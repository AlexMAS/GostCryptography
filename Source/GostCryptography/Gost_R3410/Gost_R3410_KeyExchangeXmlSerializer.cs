using System;
using System.Security;
using System.Text;

using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Базовый класс XML-сериализатора параметров ключа цифровой подписи ГОСТ Р 34.10.
	/// </summary>
	/// <typeparam name="TKeyParams">Параметры ключа цифровой подписи ГОСТ Р 34.10.</typeparam>
	public abstract class Gost_R3410_KeyExchangeXmlSerializer<TKeyParams> where TKeyParams : Gost_R3410_KeyExchangeParams
	{
		private const string OidPrefix = "urn:oid:";
		private const string PublicKeyParametersTag = "PublicKeyParameters";
		private const string PublicKeyParamSetTag = "publicKeyParamSet";
		private const string DigestParamSetTag = "digestParamSet";
		private const string EncryptionParamSetTag = "encryptionParamSet";
		private const string PublicKeyTag = "PublicKey";
		private const string PrivateKeyTag = "PrivateKey";

		private readonly string _keyValueTag;


		/// <summary>
		/// Создает новый экземпляр данного класса.
		/// </summary>
		/// <param name="keyValueTag">Имя тега с информацией о параметрах ключа.</param>
		protected Gost_R3410_KeyExchangeXmlSerializer(string keyValueTag)
		{
			_keyValueTag = keyValueTag;
		}


		/// <summary>
		/// Возвращает XML с параметрами ключа.
		/// </summary>
		public string Serialize(TKeyParams parameters)
		{
			var builder = new StringBuilder().AppendFormat("<{0}>", _keyValueTag);

			if ((parameters.DigestParamSet != null) || (parameters.EncryptionParamSet != null) || (parameters.PublicKeyParamSet != null))
			{
				builder.AppendFormat("<{0}>", PublicKeyParametersTag);
				builder.AppendFormat("<{0}>{1}{2}</{0}>", PublicKeyParamSetTag, OidPrefix, parameters.PublicKeyParamSet);
				builder.AppendFormat("<{0}>{1}{2}</{0}>", DigestParamSetTag, OidPrefix, parameters.DigestParamSet);

				if (parameters.EncryptionParamSet != null)
				{
					builder.AppendFormat("<{0}>{1}{2}</{0}>", EncryptionParamSetTag, OidPrefix, parameters.EncryptionParamSet);
				}

				builder.AppendFormat("</{0}>", PublicKeyParametersTag);
			}

			builder.AppendFormat("<{0}>{1}</{0}>", PublicKeyTag, Convert.ToBase64String(parameters.PublicKey));

			if (parameters.PrivateKey != null)
			{
				builder.AppendFormat("<{0}>{1}</{0}>", PrivateKeyTag, Convert.ToBase64String(parameters.PublicKey));
			}

			builder.AppendFormat("</{0}>", _keyValueTag);

			return builder.ToString();
		}

		/// <summary>
		/// Возвращает параметры ключа на основе XML.
		/// </summary>
		public TKeyParams Deserialize(string keyParametersXml, TKeyParams parameters)
		{
			if (string.IsNullOrEmpty(keyParametersXml))
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyParametersXml));
			}

			var keyValue = SecurityElement.FromString(keyParametersXml);

			if (keyValue == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, _keyValueTag);
			}

			keyValue = SelectChildElement(keyValue, _keyValueTag) ?? keyValue;

			var publicKeyParameters = SelectChildElement(keyValue, PublicKeyParametersTag);

			if (publicKeyParameters != null)
			{
				var publicKeyParamSet = RemoveWhiteSpaces(SelectChildElementText(publicKeyParameters, PublicKeyParamSetTag, false));

				if (!publicKeyParamSet.StartsWith(OidPrefix, StringComparison.OrdinalIgnoreCase))
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, PublicKeyParamSetTag);
				}

				parameters.PublicKeyParamSet = publicKeyParamSet.Substring(OidPrefix.Length);

				var digestParamSet = RemoveWhiteSpaces(SelectChildElementText(publicKeyParameters, DigestParamSetTag, false));

				if (!digestParamSet.StartsWith(OidPrefix, StringComparison.OrdinalIgnoreCase))
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, DigestParamSetTag);
				}

				parameters.DigestParamSet = digestParamSet.Substring(OidPrefix.Length);

				var encryptionParamSet = SelectChildElementText(publicKeyParameters, EncryptionParamSetTag, true);

				if (!string.IsNullOrEmpty(encryptionParamSet))
				{
					encryptionParamSet = RemoveWhiteSpaces(encryptionParamSet);

					if (!encryptionParamSet.StartsWith(OidPrefix, StringComparison.OrdinalIgnoreCase))
					{
						throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, EncryptionParamSetTag);
					}

					parameters.EncryptionParamSet = encryptionParamSet.Substring(OidPrefix.Length);
				}
			}

			var publicKey = SelectChildElementText(keyValue, PublicKeyTag, false);
			parameters.PublicKey = Convert.FromBase64String(RemoveWhiteSpaces(publicKey));

			var privateKey = SelectChildElementText(keyValue, PrivateKeyTag, true);

			if (privateKey != null)
			{
				parameters.PrivateKey = Convert.FromBase64String(RemoveWhiteSpaces(privateKey));
			}

			return parameters;
		}


		private static string SelectChildElementText(SecurityElement element, string childName, bool canNull)
		{
			string text = null;

			var child = SelectChildElement(element, childName);

			if (child != null && (child.Children == null || child.Children.Count == 0))
			{
				text = child.Text;
			}

			if (string.IsNullOrEmpty(text) && !canNull)
			{
				throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, childName);
			}

			return text;
		}

		private static SecurityElement SelectChildElement(SecurityElement element, string childName)
		{
			var children = element.Children;

			if (children != null)
			{
				foreach (SecurityElement child in children)
				{
					if (string.Equals(child.Tag, childName, StringComparison.OrdinalIgnoreCase)
						|| child.Tag.EndsWith(":" + childName, StringComparison.OrdinalIgnoreCase))
					{
						return child;
					}
				}
			}

			return null;
		}

		private static string RemoveWhiteSpaces(string value)
		{
			var length = value.Length;

			var countWhiteSpace = 0;

			for (var i = 0; i < length; ++i)
			{
				if (char.IsWhiteSpace(value[i]))
				{
					++countWhiteSpace;
				}
			}

			var valueWithoutWhiteSpace = new char[length - countWhiteSpace];

			for (int i = 0, j = 0; i < length; ++i)
			{
				if (!char.IsWhiteSpace(value[i]))
				{
					valueWithoutWhiteSpace[j++] = value[i];
				}
			}

			return new string(valueWithoutWhiteSpace);
		}
	}
}