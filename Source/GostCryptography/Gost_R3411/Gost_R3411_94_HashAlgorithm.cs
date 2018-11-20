using System.Security;

using GostCryptography.Native;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация алгоритма хэширования ГОСТ Р 34.11-94.
	/// </summary>
	public class Gost_R3411_94_HashAlgorithm : Gost_R3411_HashAlgorithm
	{
		/// <summary>
		/// Наименование алгоритма хэширования ГОСТ Р 34.11-94.
		/// </summary>
		public const string AlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";

		/// <summary>
		/// Устаревшее наименование алгоритма хэширования ГОСТ Р 34.11-94.
		/// </summary>
		public const string ObsoleteAlgorithmNameValue = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";

		/// <summary>
		/// Известные наименования алгоритма хэширования ГОСТ Р 34.11-94.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { AlgorithmNameValue, ObsoleteAlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_HashAlgorithm() : base(256)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_HashAlgorithm(int providerType) : base(providerType, 256)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => AlgorithmNameValue;


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override SafeHashHandleImpl CreateHashHandle(SafeProvHandleImpl providerHandle)
		{
			return CryptoApiHelper.CreateHash_3411_94(providerHandle);
		}
	}
}