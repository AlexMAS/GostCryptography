using System;
using System.Security;
using System.Security.Permissions;
using System.Text;

using GostCryptography.Asn1.Gost.Gost_R3410;
using GostCryptography.Base;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Базовый класс для всех реализаций алгоритма ГОСТ Р 34.10.
	/// </summary>
	/// <typeparam name="TKeyParams">Параметры ключа цифровой подписи ГОСТ Р 34.10.</typeparam>
	/// <typeparam name="TKeyAlgorithm">Алгоритм общего секретного ключа ГОСТ Р 34.10.</typeparam>
	public abstract class Gost_R3410_AsymmetricAlgorithmBase<TKeyParams, TKeyAlgorithm> : GostAsymmetricAlgorithm
		where TKeyParams : Gost_R3410_KeyExchangeParams
		where TKeyAlgorithm : Gost_R3410_KeyExchangeAlgorithm
	{
		private const string UrnOidXmlTerm = "urn:oid:";
		private const string KeyValueXmlTag = "GostKeyValue";
		private const string PublicKeyParametersXmlTag = "PublicKeyParameters";
		private const string PublicKeyParamSetXmlTag = "publicKeyParamSet";
		private const string DigestParamSetXmlTag = "digestParamSet";
		private const string EncryptionParamSetXmlTag = "encryptionParamSet";
		private const string PublicKeyXmlTag = "PublicKey";
		private const string PrivateKeyXmlTag = "PrivateKey";


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3410_AsymmetricAlgorithmBase()
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected Gost_R3410_AsymmetricAlgorithmBase(ProviderTypes providerType) : base(providerType)
		{
		}


		/// <summary>
		/// Идентификатор алгоритма обмена ключей.
		/// </summary>
		protected abstract int ExchangeAlgId { get; }
		/// <summary>
		/// Идентификатор алгоритма цифровой подписи.
		/// </summary>
		protected abstract int SignatureAlgId { get; }


		/// <summary>
		/// Создает экземпляр <typeparamref name="TKeyParams"/>.
		/// </summary>
		protected abstract TKeyParams CreateKeyExchangeParams();

		/// <summary>
		/// Создает экземпляр <typeparamref name="TKeyAlgorithm"/>.
		/// </summary>
		protected abstract TKeyAlgorithm CreateKeyExchangeAlgorithm(ProviderTypes providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, TKeyParams keyExchangeParameters);


		/// <summary>
		/// Создает общий секретный ключ.
		/// </summary>
		/// <param name="keyParameters">Параметры открытого ключа, используемого для создания общего секретного ключа.</param>
		public abstract TKeyAlgorithm CreateKeyExchange(TKeyParams keyParameters);


		/// <summary>
		/// Экспортирует (шифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="includePrivateKey">Включить секретный ключ.</param>
		public abstract TKeyParams ExportParameters(bool includePrivateKey);

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParameters">Параметры ключа, используемого для создания общего секретного ключа.</param>
		public abstract void ImportParameters(TKeyParams keyParameters);


		/// <summary>
		/// Экспортирует (шифрует) в XML параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="includePrivateKey">Включить секретный ключ.</param>
		public override string ToXmlString(bool includePrivateKey)
		{
			var keyParameters = ExportParameters(includePrivateKey);
			return KeyParametersToXml(keyParameters);
		}

		/// <summary>
		/// Импортирует (дешифрует) параметры ключа, используемого для создания общего секретного ключа.
		/// </summary>
		/// <param name="keyParametersXml">Параметры ключа, используемого для создания общего секретного ключа.</param>
		/// <exception cref="ArgumentNullException"></exception>
		[SecuritySafeCritical]
		[ReflectionPermission(SecurityAction.Assert, MemberAccess = true)]
		public override void FromXmlString(string keyParametersXml)
		{
			if (string.IsNullOrEmpty(keyParametersXml))
			{
				throw ExceptionUtility.ArgumentNull(nameof(keyParametersXml));
			}

			var keyParameters = KeyParametersFromXml(keyParametersXml);
			ImportParameters(keyParameters);
		}


		private static string KeyParametersToXml(TKeyParams parameters)
		{
			var builder = new StringBuilder().AppendFormat("<{0}>", KeyValueXmlTag);

			if ((parameters.DigestParamSet != null) || (parameters.EncryptionParamSet != null) || (parameters.PublicKeyParamSet != null))
			{
				builder.AppendFormat("<{0}>", PublicKeyParametersXmlTag);
				builder.AppendFormat("<{0}>{1}{2}</{0}>", PublicKeyParamSetXmlTag, UrnOidXmlTerm, parameters.PublicKeyParamSet);
				builder.AppendFormat("<{0}>{1}{2}</{0}>", DigestParamSetXmlTag, UrnOidXmlTerm, parameters.DigestParamSet);

				if (parameters.EncryptionParamSet != null)
				{
					builder.AppendFormat("<{0}>{1}{2}</{0}>", EncryptionParamSetXmlTag, UrnOidXmlTerm, parameters.EncryptionParamSet);
				}

				builder.AppendFormat("</{0}>", PublicKeyParametersXmlTag);
			}

			builder.AppendFormat("<{0}>{1}</{0}>", PublicKeyXmlTag, Convert.ToBase64String(parameters.PublicKey));

			if (parameters.PrivateKey != null)
			{
				builder.AppendFormat("<{0}>{1}</{0}>", PrivateKeyXmlTag, Convert.ToBase64String(parameters.PublicKey));
			}

			builder.AppendFormat("</{0}>", KeyValueXmlTag);

			return builder.ToString();
		}

		[SecurityCritical]
		private TKeyParams KeyParametersFromXml(string keyParametersXml)
		{
			var parameters = CreateKeyExchangeParams();

			var keyValue = SecurityElement.FromString(keyParametersXml);

			if (keyValue == null)
			{
				throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, KeyValueXmlTag);
			}

			keyValue = SelectChildElement(keyValue, KeyValueXmlTag) ?? keyValue;

			var publicKeyParameters = SelectChildElement(keyValue, PublicKeyParametersXmlTag);

			if (publicKeyParameters != null)
			{
				var publicKeyParamSet = RemoveWhiteSpaces(SelectChildElementText(publicKeyParameters, PublicKeyParamSetXmlTag, false));

				if (!publicKeyParamSet.StartsWith(UrnOidXmlTerm, StringComparison.OrdinalIgnoreCase))
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, PublicKeyParamSetXmlTag);
				}

				parameters.PublicKeyParamSet = publicKeyParamSet.Substring(UrnOidXmlTerm.Length);

				var digestParamSet = RemoveWhiteSpaces(SelectChildElementText(publicKeyParameters, DigestParamSetXmlTag, false));

				if (!digestParamSet.StartsWith(UrnOidXmlTerm, StringComparison.OrdinalIgnoreCase))
				{
					throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, DigestParamSetXmlTag);
				}

				parameters.DigestParamSet = digestParamSet.Substring(UrnOidXmlTerm.Length);

				var encryptionParamSet = SelectChildElementText(publicKeyParameters, EncryptionParamSetXmlTag, true);

				if (!string.IsNullOrEmpty(encryptionParamSet))
				{
					encryptionParamSet = RemoveWhiteSpaces(encryptionParamSet);

					if (!encryptionParamSet.StartsWith(UrnOidXmlTerm, StringComparison.OrdinalIgnoreCase))
					{
						throw ExceptionUtility.CryptographicException(Resources.InvalidFromXmlString, EncryptionParamSetXmlTag);
					}

					parameters.EncryptionParamSet = encryptionParamSet.Substring(UrnOidXmlTerm.Length);
				}
			}

			var publicKey = SelectChildElementText(keyValue, PublicKeyXmlTag, false);
			parameters.PublicKey = Convert.FromBase64String(RemoveWhiteSpaces(publicKey));

			var privateKey = SelectChildElementText(keyValue, PrivateKeyXmlTag, true);

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