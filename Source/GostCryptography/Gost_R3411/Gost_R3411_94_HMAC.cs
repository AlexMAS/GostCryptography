using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация HMAC на базе алгоритма хэширования ГОСТ Р 34.11-94.
	/// </summary>
	public sealed class Gost_R3411_94_HMAC : Gost_R3411_HMAC<Gost_R3411_94_HashAlgorithm>
	{
		/// <summary>
		/// Наименование алгоритма HMAC на базе ГОСТ Р 34.11-94.
		/// </summary>
		public const string AlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:hmac-gostr3411";

		/// <summary>
		/// Устаревшее наименование алгоритма HMAC на базе ГОСТ Р 34.11-94.
		/// </summary>
		public const string ObsoleteAlgorithmNameValue = "http://www.w3.org/2001/04/xmldsig-more#hmac-gostr3411";

		/// <summary>
		/// Известные наименования алгоритма HMAC на базе ГОСТ Р 34.11-94.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue, ObsoleteAlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_HMAC() : base(Gost_R3411_94_HashAlgorithm.DefaultHashSizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_HMAC(ProviderType providerType) : base(providerType, Gost_R3411_94_HashAlgorithm.DefaultHashSizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_HMAC(Gost_28147_89_SymmetricAlgorithmBase keyAlgorithm) : base(keyAlgorithm, Gost_R3411_94_HashAlgorithm.DefaultHashSizeValue)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => AlgorithmNameValue;


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override SafeHashHandleImpl CreateHashHMAC(ProviderType providerType, SafeProvHandleImpl providerHandle, SafeKeyHandleImpl symKeyHandle)
		{
			return CryptoApiHelper.CreateHashHMAC_94(providerType, providerHandle, symKeyHandle);
		}
	}
}