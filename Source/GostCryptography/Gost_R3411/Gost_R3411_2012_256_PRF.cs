﻿using System.Security;

using GostCryptography.Base;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация PRF на базе алгоритма хэширования ГОСТ Р 34.11-2012/256.
	/// </summary>
	public sealed class Gost_R3411_2012_256_PRF : Gost_R3411_PRF<Gost_R3411_2012_256_HMAC>
	{
		/// <summary>
		/// Наименование алгоритма PRF на базе ГОСТ Р 34.11-2012/256 для использования в протоколе WS-Trust.
		/// </summary>
		public const string WsTrustAlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:ck-p-gostr3411-2012-256";

		/// <summary>
		/// Наименование алгоритма PRF на базе ГОСТ Р 34.11-2012/256 для использования в протоколах на базе WS-SecureConversation.
		/// </summary>
		public const string WsSecureConversationAlgorithmNameValue = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:dk-p-gostr3411-2012-256";

		/// <summary>
		/// Известные наименования алгоритма PRF на базе ГОСТ Р 34.11-2012/256.
		/// </summary>
		public static readonly string[] KnownAlgorithmNames = { WsTrustAlgorithmNameValue, WsSecureConversationAlgorithmNameValue };


		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_256_PRF(GostSymmetricAlgorithm key, byte[] label, byte[] seed) : base(key, label, seed)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_2012_256_PRF(ProviderType providerType, byte[] key, byte[] label, byte[] seed) : base(providerType, key, label, seed)
		{
		}


		/// <inheritdoc />
		public override string AlgorithmName => WsTrustAlgorithmNameValue;


		/// <inheritdoc />
		[SecuritySafeCritical]
		protected override Gost_R3411_2012_256_HMAC CreateHMAC(GostSymmetricAlgorithm key)
		{
			return new Gost_R3411_2012_256_HMAC(key);
		}
	}
}