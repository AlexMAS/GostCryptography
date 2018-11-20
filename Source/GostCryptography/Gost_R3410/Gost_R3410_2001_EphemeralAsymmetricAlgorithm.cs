using System.Security;

using GostCryptography.Asn1.Gost.Gost_R3410_2001;
using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2001 на основе эфимерного ключа.
	/// </summary>
	public sealed class Gost_R3410_2001_EphemeralAsymmetricAlgorithm : Gost_R3410_EphemeralAsymmetricAlgorithm<Gost_R3410_2001_KeyExchangeParams, Gost_R3410_2001_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2001.
		/// </summary>
		public const string SignatureAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2001.
		/// </summary>
		public const string KeyExchangeAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2001";


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2001_EphemeralAsymmetricAlgorithm()
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2001_EphemeralAsymmetricAlgorithm(int providerType) : base(providerType)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2001_EphemeralAsymmetricAlgorithm(Gost_R3410_2001_KeyExchangeParams keyParameters) : base(keyParameters)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2001_EphemeralAsymmetricAlgorithm(int providerType, Gost_R3410_2001_KeyExchangeParams keyParameters) : base(providerType, keyParameters)
		{
		}


		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmValue;


		/// <inheritdoc />
		protected override int ExchangeAlgId => Constants.CALG_DH_EL_EPHEM;

		/// <inheritdoc />
		protected override int SignatureAlgId => Constants.CALG_GR3410EL;


		/// <inheritdoc />
		protected override Gost_R3410_2001_KeyExchangeParams CreateKeyExchangeParams()
		{
			return new Gost_R3410_2001_KeyExchangeParams();
		}

		/// <inheritdoc />
		protected override Gost_R3410_2001_KeyExchangeAlgorithm CreateKeyExchangeAlgorithm(int providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_2001_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2001_KeyExchangeAlgorithm(providerType, provHandle, keyHandle, keyExchangeParameters);
		}


		/// <inheritdoc />
		public override GostKeyExchangeFormatter CreatExchangeFormatter()
		{
			return new Gost_R3410_2001_KeyExchangeFormatter(this);
		}

		/// <inheritdoc />
		public override GostKeyExchangeDeformatter CreateKeyExchangeDeformatter()
		{
			return new Gost_R3410_2001_KeyExchangeDeformatter(this);
		}
	}
}