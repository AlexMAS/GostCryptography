using System.Security;

using GostCryptography.Asn1.Gost.Gost_R3410_2012_512;
using GostCryptography.Base;
using GostCryptography.Config;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2012/512 на основе эфимерного ключа.
	/// </summary>
	public sealed class Gost_R3410_2012_512_EphemeralAsymmetricAlgorithm : Gost_R3410_EphemeralAsymmetricAlgorithm<Gost_R3410_2012_512_KeyExchangeParams, Gost_R3410_2012_512_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Размер ключа ГОСТ Р 34.10-2012/512.
		/// </summary>
		public const int DefaultKeySizeValue = 1024;

		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 512 бит.
		/// </summary>
		public const string SignatureAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2012 для ключей длины 512 бит.
		/// </summary>
		public const string KeyExchangeAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-512";


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_EphemeralAsymmetricAlgorithm() : this(GostCryptoConfig.ProviderType_2012_1024)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_EphemeralAsymmetricAlgorithm(ProviderType providerType) : base(providerType, DefaultKeySizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_EphemeralAsymmetricAlgorithm(Gost_R3410_2012_512_KeyExchangeParams keyParameters) : this(GostCryptoConfig.ProviderType_2012_1024, keyParameters)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_EphemeralAsymmetricAlgorithm(ProviderType providerType, Gost_R3410_2012_512_KeyExchangeParams keyParameters) : base(providerType, keyParameters, DefaultKeySizeValue)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmValue;


		/// <inheritdoc />
		protected override int ExchangeAlgId => Constants.CALG_DH_GR3410_12_512_EPHEM;

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