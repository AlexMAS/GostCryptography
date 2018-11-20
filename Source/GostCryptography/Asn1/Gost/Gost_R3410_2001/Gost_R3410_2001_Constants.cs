namespace GostCryptography.Asn1.Gost.Gost_R3410_2001
{
	public static class Gost_R3410_2001_Constants
	{
		/// <summary>
		/// Алгоритм ГОСТ Р 34.10-2001, используемый при экспорте/импорте ключей.
		/// </summary>
		public static readonly OidValue KeyAlgorithm = OidValue.FromString("1.2.643.2.2.19");

		/// <summary>
		/// Алгоритм Диффи-Хеллмана на базе эллиптической кривой.
		/// </summary>
		public static readonly OidValue DhAlgorithm = OidValue.FromString("1.2.643.2.2.98");

		/// <summary>
		/// Алгоритм цифровой подписи ГОСТ Р 34.10-2001.
		/// </summary>
		public static readonly OidValue SignatureAlgorithm = OidValue.FromString("1.2.643.2.2.3");

		/// <summary>
		/// Функция хэширования ГОСТ Р 34.11-94.
		/// </summary>
		public static readonly OidValue HashAlgorithm = OidValue.FromString("1.2.643.2.2.9");
	}
}