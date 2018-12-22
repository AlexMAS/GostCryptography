using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация PRF на базе алгоритма хэширования ГОСТ Р 34.11-94.
	/// </summary>
	public sealed class Gost_R3411_94_PRF : Gost_R3411_PRF<Gost_R3411_94_HMAC>
	{
		/// <summary>
		/// Наименование алгоритма PRF на базе ГОСТ Р 34.11-94 для использования в протоколе WS-Trust.
		/// </summary>
		public const string WsTrustAlgorithmNameValue = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PGOSTR3411";

		/// <summary>
		/// Наименование алгоритма PRF на базе ГОСТ Р 34.11-94 для использования в протоколах на базе WS-SecureConversation.
		/// </summary>
		public const string WsSecureConversationAlgorithmNameValue = "http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512/dk/p_gostr3411";

		/// <summary>
		/// Известные наименования алгоритма PRF на базе ГОСТ Р 34.11-94.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { WsTrustAlgorithmNameValue, WsSecureConversationAlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_PRF(Gost_28147_89_SymmetricAlgorithmBase key, byte[] label, byte[] seed) : base(key, label, seed)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_PRF(ProviderType providerType, byte[] key, byte[] label, byte[] seed) : base(providerType, key, label, seed)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => WsTrustAlgorithmNameValue;


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override Gost_R3411_94_HMAC CreateHMAC(Gost_28147_89_SymmetricAlgorithm key)
		{
			return new Gost_R3411_94_HMAC(key);
		}
	}
}