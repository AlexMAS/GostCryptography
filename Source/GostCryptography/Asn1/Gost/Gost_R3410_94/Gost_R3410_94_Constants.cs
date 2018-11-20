namespace GostCryptography.Asn1.Gost.Gost_R3410_94
{
	public static class Gost_R3410_94_Constants
	{
		/// <summary>
		/// Алгоритм ГОСТ Р 34.10-94, используемый при экспорте/импорте ключей.
		/// </summary>
		public static readonly OidValue KeyAlgorithm = OidValue.FromString("1.2.643.2.2.20");

		/// <summary>
		/// Алгоритм Диффи-Хеллмана на базе потенциальной функции.
		/// </summary>
		public static readonly OidValue DhAlgorithm = OidValue.FromString("1.2.643.2.2.99");

		/// <summary>
		/// Алгоритм цифровой подписи ГОСТ Р 34.10-94.
		/// </summary>
		public static readonly OidValue SignatureAlgorithm = OidValue.FromString("1.2.643.2.2.4");

		/// <summary>
		/// Функция хэширования ГОСТ Р 34.11-94.
		/// </summary>
		public static readonly OidValue HashAlgorithm = OidValue.FromString("1.2.643.2.2.9");
	}
}