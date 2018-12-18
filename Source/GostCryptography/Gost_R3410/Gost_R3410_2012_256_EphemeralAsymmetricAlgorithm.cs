using System.Security;

using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;
using GostCryptography.Base;
using GostCryptography.Config;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2012/256 на основе эфимерного ключа.
	/// </summary>
	public sealed class Gost_R3410_2012_256_EphemeralAsymmetricAlgorithm : Gost_R3410_EphemeralAsymmetricAlgorithm<Gost_R3410_2012_256_KeyExchangeParams, Gost_R3410_2012_256_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Размер ключа ГОСТ Р 34.10-2012/256.
		/// </summary>
		public const int DefaultKeySizeValue = 512;

		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 256 бит.
		/// </summary>
		public const string SignatureAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2012 для ключей длины 256 бит.
		/// </summary>
		public const string KeyExchangeAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256";


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_256_EphemeralAsymmetricAlgorithm() : this(GostCryptoConfig.ProviderType_2012_512)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_256_EphemeralAsymmetricAlgorithm(ProviderType providerType) : base(providerType, DefaultKeySizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_256_EphemeralAsymmetricAlgorithm(Gost_R3410_2012_256_KeyExchangeParams keyParameters) : this(GostCryptoConfig.ProviderType_2012_512, keyParameters)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_256_EphemeralAsymmetricAlgorithm(ProviderType providerType, Gost_R3410_2012_256_KeyExchangeParams keyParameters) : base(providerType, keyParameters, DefaultKeySizeValue)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmValue;


		/// <inheritdoc />
		protected override int ExchangeAlgId => Constants.CALG_DH_GR3410_12_256_EPHEM;

		/// <inheritdoc />
		protected override int SignatureAlgId => Constants.CALG_GR3410_2012_256;


		/// <inheritdoc />
		protected override Gost_R3410_2012_256_KeyExchangeParams CreateKeyExchangeParams()
		{
			return new Gost_R3410_2012_256_KeyExchangeParams();
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override Gost_R3410_2012_256_KeyExchangeAlgorithm CreateKeyExchangeAlgorithm(ProviderType providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_2012_256_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2012_256_KeyExchangeAlgorithm(providerType, provHandle, keyHandle, keyExchangeParameters, KeySizeValue, SignatureAlgId);
		}


		/// <inheritdoc />
		[SecuritySafeCritical]
		public override GostHashAlgorithm CreateHashAlgorithm()
		{
			return new Gost_R3411_2012_256_HashAlgorithm(ProviderType, this.GetSafeHandle<SafeProvHandleImpl>());
		}


		/// <inheritdoc />
		public override GostKeyExchangeFormatter CreateKeyExchangeFormatter()
		{
			return new Gost_R3410_2012_256_KeyExchangeFormatter(this);
		}

		/// <inheritdoc />
		public override GostKeyExchangeDeformatter CreateKeyExchangeDeformatter()
		{
			return new Gost_R3410_2012_256_KeyExchangeDeformatter(this);
		}

		/// <inheritdoc />
		protected override Gost_R3410_KeyExchangeXmlSerializer<Gost_R3410_2012_256_KeyExchangeParams> CreateKeyExchangeXmlSerializer()
		{
			return new Gost_R3410_2012_256_KeyExchangeXmlSerializer();
		}
	}
}