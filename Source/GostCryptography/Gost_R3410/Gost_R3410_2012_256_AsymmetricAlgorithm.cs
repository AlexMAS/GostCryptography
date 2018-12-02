using System.Security;
using System.Security.Cryptography;
using System.Security.Permissions;

using GostCryptography.Asn1.Gost.Gost_R3410_2012_256;
using GostCryptography.Base;
using GostCryptography.Gost_R3411;
using GostCryptography.Native;
using GostCryptography.Properties;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Реализация алгоритма ГОСТ Р 34.10-2012/256.
	/// </summary>
	[SecurityCritical]
	[SecuritySafeCritical]
	public sealed class Gost_R3410_2012_256_AsymmetricAlgorithm : Gost_R3410_AsymmetricAlgorithm<Gost_R3410_2012_256_KeyExchangeParams, Gost_R3410_2012_256_KeyExchangeAlgorithm>
	{
		/// <summary>
		/// Наименование алгоритма цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 256 бит.
		/// </summary>
		public const string SignatureAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";

		/// <summary>
		/// Наименование алгоритма обмена ключами ГОСТ Р 34.10-2012 для ключей длины 256 бит.
		/// </summary>
		public const string KeyExchangeAlgorithmValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256";


		/// <inheritdoc />
		[SecurityCritical]
		[SecuritySafeCritical]
		public Gost_R3410_2012_256_AsymmetricAlgorithm()
		{
		}

		/// <inheritdoc />
		[SecurityCritical]
		[SecuritySafeCritical]
		[ReflectionPermission(SecurityAction.Assert, MemberAccess = true)]
		public Gost_R3410_2012_256_AsymmetricAlgorithm(ProviderTypes providerType) : base(providerType)
		{
		}

		/// <inheritdoc />
		[SecurityCritical]
		[SecuritySafeCritical]
		public Gost_R3410_2012_256_AsymmetricAlgorithm(CspParameters providerParameters) : base(providerParameters)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string SignatureAlgorithm => SignatureAlgorithmValue;

		/// <inheritdoc />
		public override string KeyExchangeAlgorithm => KeyExchangeAlgorithmValue;


		/// <inheritdoc />
		protected override int ExchangeAlgId => Constants.CALG_DH_GR3410_2012_256_SF;

		/// <inheritdoc />
		protected override int SignatureAlgId => Constants.CALG_GR3410_2012_256;


		/// <inheritdoc />
		protected override Gost_R3410_2012_256_KeyExchangeParams CreateKeyExchangeParams()
		{
			return new Gost_R3410_2012_256_KeyExchangeParams();
		}

		/// <inheritdoc />
		protected override Gost_R3410_2012_256_KeyExchangeAlgorithm CreateKeyExchangeAlgorithm(ProviderTypes providerType, SafeProvHandleImpl provHandle, SafeKeyHandleImpl keyHandle, Gost_R3410_2012_256_KeyExchangeParams keyExchangeParameters)
		{
			return new Gost_R3410_2012_256_KeyExchangeAlgorithm(providerType, provHandle, keyHandle, keyExchangeParameters);
		}


		/// <inheritdoc />
		public override GostHashAlgorithm CreateHashAlgorithm()
		{
			return new Gost_R3411_2012_256_HashAlgorithm(ProviderType);
		}

		/// <inheritdoc />
		protected override void ValidateHashParameter(byte[] hash)
		{
			if (hash == null)
			{
				throw ExceptionUtility.ArgumentNull(nameof(hash));
			}

			if (hash.Length != Gost_R3411_2012_256_HashAlgorithm.DefaultHashSizeValue / 8)
			{
				throw ExceptionUtility.ArgumentOutOfRange(nameof(hash), Resources.InvalidHashSize, Gost_R3411_2012_256_HashAlgorithm.DefaultHashSizeValue / 8);
			}
		}


		/// <inheritdoc />
		public override GostKeyExchangeFormatter CreatKeyExchangeFormatter()
		{
			return new Gost_R3410_2012_256_KeyExchangeFormatter(this);
		}

		/// <inheritdoc />
		public override GostKeyExchangeDeformatter CreateKeyExchangeDeformatter()
		{
			return new Gost_R3410_2012_256_KeyExchangeDeformatter(this);
		}
	}
}