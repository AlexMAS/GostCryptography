using System.Security;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410_2001;
using GostCryptography.Base;
using GostCryptography.Config;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class Gost_R3410_2001_AsymmetricAlgorithm : Gost_R3410_AsymmetricAlgorithm<Gost_R3410_2001_KeyExchangeParams, Gost_R3410_2001_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Размер ключа ГОСТ Р 34.10-2001.
		/// </summary>
		public const int DefaultKeySizeValue = 512;

		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2001.
		/// </summary>
		public const string SignatureAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";

		/// <summary>
		/// Устаревшее наименование алгоритма цифровой подписи ГОСТ Р 34.10-2001.
		/// </summary>
		public const string ObsoleteSignatureAlgorithmValue = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2001.
		/// </summary>
		public const string KeyExchangeAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2001";

		/// <summary>
		/// Известные наименования алгоритма цифровой подписи ГОСТ Р 34.10-2001.
		/// </summary>
		public static readonly string[] KnownSignatureAlgorithmNames = { SignatureAlgorithmValue, ObsoleteSignatureAlgorithmValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2001_AsymmetricAlgorithm() : this(GostCryptoConfig.ProviderType)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2001_AsymmetricAlgorithm(ProviderType providerType) : base(providerType, DefaultKeySizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2001_AsymmetricAlgorithm(CspParameters providerParameters) : base(providerParameters, DefaultKeySizeValue)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmValue;


		/// <inheritdoc />
		protected override int ExchangeAlgId => Constants.CALG_DH_EL_SF;

		/// <inheritdoc />
		protected override int SignatureAlgId => Constants.CALG_GR3410EL;


		/// <inheritdoc />
		protected override Gost_R3410_2001_KeyExchangeParams CreateKeyExchangeParams()
		{
			return new Gost_R3410_2001_KeyExchangeParams();
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override Gost_R3410_2001_KeyExchangeAlgorithm CreateKeyExchangeAlgorithm(ProviderType providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_2001_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2001_KeyExchangeAlgorithm(providerType, provHandle, keyHandle, keyExchangeParameters, KeySizeValue, SignatureAlgId);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override GostHashAlgorithm CreateHashAlgorithm()
		{
			return new Gost_R3411_94_HashAlgorithm(ProviderType, this.GetSafeHandle<SafeProvHandleImpl>());
		}

		/// <inheritdoc />
		protected override void ValidateHashParameter(byte[] hash)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hash));
			}

			if (hash.Length != Gost_R3411_94_HashAlgorithm.DefaultHashSizeValue / 8)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(hash), Resources.InvalidHashSize, Gost_R3411_94_HashAlgorithm.DefaultHashSizeValue / 8);
			}
		}


		/// <inheritdoc />
		public override GostKeyExchangeFormatter CreateKeyExchangeFormatter()
		{
			return new Gost_R3410_2001_KeyExchangeFormatter(this);
		}

		/// <inheritdoc />
		public override GostKeyExchangeDeformatter CreateKeyExchangeDeformatter()
		{
			return new Gost_R3410_2001_KeyExchangeDeformatter(this);
		}

		/// <inheritdoc />
		protected override Gost_R3410_KeyExchangeXmlSerializer<Gost_R3410_2001_KeyExchangeParams> CreateKeyExchangeXmlSerializer()
		{
			return new Gost_R3410_2001_KeyExchangeXmlSerializer();
		}
	}
}