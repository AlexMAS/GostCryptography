using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Asn1.Gost.Gost_R3410_2012_512;
using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2012/512.
	/// </summary>
	[SecurityCritical]
	[SecuritySafeCritical]
	public sealed class Gost_R3410_2012_512_AsymmetricAlgorithm : Gost_R3410_AsymmetricAlgorithm<Gost_R3410_2012_512_KeyExchangeParams, Gost_R3410_2012_512_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 512 бит.
		/// </summary>
		public const string SignatureAlgorithmName = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2012 для ключей длины 512 бит.
		/// </summary>
		public const string KeyExchangeAlgorithmName = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-512";


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_AsymmetricAlgorithm()
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		[ReflectionPermission(SecurityAction.Assert, MemberAccess = true)]
		public Gost_R3410_2012_512_AsymmetricAlgorithm(int providerType) : base(providerType)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3410_2012_512_AsymmetricAlgorithm(CspParameters providerParameters) : base(providerParameters)
		{
		}


		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmName;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmName;


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
		protected override Gost_R3410_2012_512_KeyExchangeAlgorithm CreateKeyExchangeAlgorithm(int providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_2012_512_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2012_512_KeyExchangeAlgorithm(providerType, provHandle, keyHandle, keyExchangeParameters);
		}


		/// <inheritdoc />
		public override GostKeyExchangeFormatter CreatExchangeFormatter()
		{
			return new Gost_R3410_2012_512_KeyExchangeFormatter(this);
		}

		/// <inheritdoc />
		public override GostKeyExchangeDeformatter CreateKeyExchangeDeformatter()
		{
			return new Gost_R3410_2012_512_KeyExchangeDeformatter(this);
		}
	}
}