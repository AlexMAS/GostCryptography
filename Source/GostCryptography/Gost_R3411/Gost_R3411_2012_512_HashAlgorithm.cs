using System.Security;

using GostCryptography.Base;
using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация алгоритма хэширования ГОСТ Р 34.11-2012/512.
	/// </summary>
	public sealed class Gost_R3411_2012_512_HashAlgorithm : Gost_R3411_HashAlgorithm
	{
		/// <summary>
		/// Размер хэша ГОСТ Р 34.11-2012/512.
		/// </summary>
		public const int DefaultHashSizeValue = 512;

		/// <summary>
		/// Наименование алгоритма хэширования ГОСТ Р 34.11-2012/512.
		/// </summary>
		public const string AlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";

		/// <summary>
		/// Известные наименования алгоритма хэширования ГОСТ Р 34.11-2012/512.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_512_HashAlgorithm() : base(DefaultHashSizeValue)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_512_HashAlgorithm(ProviderType providerType) : base(providerType, DefaultHashSizeValue)
		{
		}

		[SecurityCritical]
		internal Gost_R3411_2012_512_HashAlgorithm(ProviderType providerType, SafeProvHandleImpl providerHandle) : base(providerType, providerHandle, DefaultHashSizeValue)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => AlgorithmNameValue;


		/// <inheritdoc />
		[SecurityCritical]
		protected override SafeHashHandleImpl CreateHashHandle(SafeProvHandleImpl providerHandle)
		{
			return CryptoApiHelper.CreateHash_3411_2012_512(providerHandle);
		}
	}
}