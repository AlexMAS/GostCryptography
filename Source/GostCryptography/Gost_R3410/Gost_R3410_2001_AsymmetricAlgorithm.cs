using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Asn1.Gost.Gost_R3410_2001;
using GostCryptography.Base;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2001.
	/// </summary>
	[SecurityCritical]
	[SecuritySafeCritical]
	public sealed class Gost_R3410_2001_AsymmetricAlgorithm : Gost_R3410_AsymmetricAlgorithm<Gost_R3410_2001_KeyExchangeParams, Gost_R3410_2001_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2001.
		/// </summary>
		public const string SignatureAlgorithmName = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2001.
		/// </summary>
		public const string KeyExchangeAlgorithmName = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2001";


		/// <inheritdoc />
		[SecurityCritical]
		[SecuritySafeCritical]
		public Gost_R3410_2001_AsymmetricAlgorithm()
		{
		}

		/// <inheritdoc />
		[SecurityCritical]
		[SecuritySafeCritical]
		[ReflectionPermission(SecurityAction.Assert, MemberAccess = true)]
		public Gost_R3410_2001_AsymmetricAlgorithm(ProviderTypes providerType) : base(providerType)
		{
		}

		/// <inheritdoc />
		[SecurityCritical]
		[SecuritySafeCritical]
		public Gost_R3410_2001_AsymmetricAlgorithm(CspParameters providerParameters) : base(providerParameters)
		{
		}


		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmName;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmName;


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
		protected override Gost_R3410_2001_KeyExchangeAlgorithm CreateKeyExchangeAlgorithm(ProviderTypes providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_2001_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2001_KeyExchangeAlgorithm(providerType, provHandle, keyHandle, keyExchangeParameters);
		}


		/// <inheritdoc />
		public override GostHashAlgorithm CreateHashAlgorithm()
		{
			return new Gost_R3411_94_HashAlgorithm(ProviderType);
		}


		/// <inheritdoc />
		public override GostKeyExchangeFormatter CreatKeyExchangeFormatter()
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