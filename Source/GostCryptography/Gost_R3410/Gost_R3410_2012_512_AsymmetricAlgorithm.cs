using System.Security;
using System.Security.Cryptography;

using GostCryptography.Asn1.Gost.Gost_R3410_2012_512;
using GostCryptography.Base;
using GostCryptography.Config;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2012/512.
	/// </summary>
	public sealed class Gost_R3410_2012_512_AsymmetricAlgorithm : Gost_R3410_AsymmetricAlgorithm<Gost_R3410_2012_512_KeyExchangeParams, Gost_R3410_2012_512_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Размер ключа ГОСТ Р 34.10-2012/512.
		/// </summary>
		public const int DefaultKeySizeValue = 1024;

		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2012/512.
		/// </summary>
		public const string SignatureAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2012/512.
		/// </summary>
		public const string KeyExchangeAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-512";

		/// <summary>
		/// Известные наименования алгоритма цифровой подписи ГОСТ Р 34.10-2012/512.
		/// </summary>
		public static readonly string[] KnownSignatureAlgorithmNames = { SignatureAlgorithmValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_AsymmetricAlgorithm() : this(GostCryptoConfig.ProviderType_2012_1024)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_AsymmetricAlgorithm(ProviderType providerType) : base(providerType, DefaultKeySizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_AsymmetricAlgorithm(CspParameters providerParameters) : base(providerParameters, DefaultKeySizeValue)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmValue;


		/// <inheritdoc />
		protected override int ExchangeAlgId => Constants.CALG_DH_GR3410_2012_512_SF;

		/// <inheritdoc />
		protected override int SignatureAlgId => Constants.CALG_GR3410_2012_512;


		/// <inheritdoc />
		protected override Gost_R3410_2012_512_KeyExchangeParams CreateKeyExchangeParams()
		{
			return new Gost_R3410_2012_512_KeyExchangeParams();
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override Gost_R3410_2012_512_KeyExchangeAlgorithm CreateKeyExchangeAlgorithm(ProviderType providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_2012_512_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2012_512_KeyExchangeAlgorithm(providerType, provHandle, keyHandle, keyExchangeParameters, KeySizeValue, SignatureAlgId);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override GostHashAlgorithm CreateHashAlgorithm()
		{
			return new Gost_R3411_2012_512_HashAlgorithm(ProviderType, this.GetSafeHandle<SafeProvHandleImpl>());
		}

		/// <inheritdoc />
		protected override void ValidateHashParameter(byte[] hash)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hash));
			}

			if (hash.Length != Gost_R3411_2012_512_HashAlgorithm.DefaultHashSizeValue / 8)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(hash), Resources.InvalidHashSize, Gost_R3411_2012_512_HashAlgorithm.DefaultHashSizeValue / 8);
			}
		}


		/// <inheritdoc />
		public override GostKeyExchangeFormatter CreateKeyExchangeFormatter()
		{
			return new Gost_R3410_2012_512_KeyExchangeFormatter(this);
		}

		/// <inheritdoc />
		public override GostKeyExchangeDeformatter CreateKeyExchangeDeformatter()
		{
			return new Gost_R3410_2012_512_KeyExchangeDeformatter(this);
		}

		/// <inheritdoc />
		protected override Gost_R3410_KeyExchangeXmlSerializer<Gost_R3410_2012_512_KeyExchangeParams> CreateKeyExchangeXmlSerializer()
		{
			return new Gost_R3410_2012_512_KeyExchangeXmlSerializer();
		}
	}
}