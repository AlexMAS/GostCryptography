namespace GostCryptography.Asn1.PKI.GostR34102001
{
	static class GostR34102001Constants
	{
		/// <summary>
		/// Идентификатор OID алгоритма ГОСТ Р 34.10-2001, используемый при экспорте/импорте ключей.
		/// </summary>
		public const string IdGostR34102001String = "1.2.643.2.2.19";

		/// <summary>
		/// Идентификатор OID алгоритма ГОСТ Р 34.10-2001, используемый при экспорте/импорте ключей.
		/// </summary>
		/// <remarks>
		/// 1.2.643.2.2.19
		/// </remarks>
		public static readonly int[] IdGostR34102001 = { 1, 2, 643, 2, 2, 19 };

		/// <summary>
		/// Идентификатор OID алгоритма Диффи-Хеллмана на базе эллиптической кривой.
		/// </summary>
		/// <remarks>
		/// 1.2.643.2.2.98
		/// </remarks>
		public static readonly int[] IdGostR34102001Dh = { 1, 2, 643, 2, 2, 98 };

		/// <summary>
		/// Идентификатор OID алгоритм цифровой подписи ГОСТ Р 34.10-2001.
		/// </summary>
		/// <remarks>
		/// 1.2.643.2.2.3
		/// </remarks>
		public static readonly int[] IdGostR341194WithGostR34102001 = { 1, 2, 643, 2, 2, 3 };
	}
}