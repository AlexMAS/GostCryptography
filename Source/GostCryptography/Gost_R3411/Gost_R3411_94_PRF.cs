using System.Security;

using GostCryptography.Base;
using GostCryptography.Gost_28147_89;

namespace GostCryptography.Gost_R3411
{
	/// <summary>
	/// Реализация PRF на базе алгоритма хэширования ГОСТ Р 34.11-94.
	/// </summary>
	public sealed class Gost_R3411_94_PRF : Gost_R3411_PRF
	{
		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_PRF(Gost_28147_89_SymmetricAlgorithmBase key, byte[] label, byte[] seed) : base(key, label, seed)
		{
		}

		/// <inheritdoc />
		[SecuritySafeCritical]
		public Gost_R3411_94_PRF(ProviderTypes providerType, byte[] key, byte[] label, byte[] seed) : base(providerType, key, label, seed)
		{
		}
	}
}