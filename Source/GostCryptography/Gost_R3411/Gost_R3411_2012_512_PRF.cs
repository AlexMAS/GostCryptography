using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация PRF на базе алгоритма хэширования ГОСТ Р 34.11-2012/512.
	/// </summary>
	public sealed class Gost_R3411_2012_512_PRF : Gost_R3411_PRF<Gost_R3411_2012_512_HMAC>
	{
		/// <summary>
		/// Наименование алгоритма PRF на базе ГОСТ Р 34.11-2012/512 для использования в протоколе WS-Trust.
		/// </summary>
		public const string WsTrustAlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:ck-p-gostr3411-2012-512";

		/// <summary>
		/// Наименование алгоритма PRF на базе ГОСТ Р 34.11-2012/512 для использования в протоколах на базе WS-SecureConversation.
		/// </summary>
		public const string WsSecureConversationAlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:dk-p-gostr3411-2012-512";

		/// <summary>
		/// Известные наименования алгоритма PRF на базе ГОСТ Р 34.11-2012/512.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { WsTrustAlgorithmNameValue, WsSecureConversationAlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_512_PRF(Gost_28147_89_SymmetricAlgorithmBase key, byte[] label, byte[] seed) : base(key, label, seed)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_512_PRF(ProviderType providerType, byte[] key, byte[] label, byte[] seed) : base(providerType, key, label, seed)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => WsTrustAlgorithmNameValue;


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override Gost_R3411_2012_512_HMAC CreateHMAC(Gost_28147_89_SymmetricAlgorithm key)
		{
			return new Gost_R3411_2012_512_HMAC(key);
		}
	}
}