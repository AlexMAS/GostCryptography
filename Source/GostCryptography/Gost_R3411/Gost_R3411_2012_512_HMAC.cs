using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация HMAC на базе алгоритма хэширования ГОСТ Р 34.11-2012/512.
	/// </summary>
	public sealed class Gost_R3411_2012_512_HMAC : Gost_R3411_HMAC<Gost_R3411_2012_512_HashAlgorithm>
	{
		/// <summary>
		/// Наименование алгоритма HMAC на базе ГОСТ Р 34.11-2012/512.
		/// </summary>
		public const string AlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr34112012-512";

		/// <summary>
		/// Известные наименования алгоритма HMAC на базе ГОСТ Р 34.11-2012/512.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_512_HMAC() : base(Gost_R3411_2012_512_HashAlgorithm.DefaultHashSizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_512_HMAC(ProviderType providerType) : base(providerType, Gost_R3411_2012_512_HashAlgorithm.DefaultHashSizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_512_HMAC(Gost_28147_89_SymmetricAlgorithmBase keyAlgorithm) : base(keyAlgorithm, Gost_R3411_2012_512_HashAlgorithm.DefaultHashSizeValue)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => AlgorithmNameValue;


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override SafeHashHandleImpl CreateHashHMAC(ProviderType providerType, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle)
		{
			return CryptoApiHelper.CreateHashHMAC_2012_512(providerType, providerHandle, symKeyHandle);
		}
	}
}