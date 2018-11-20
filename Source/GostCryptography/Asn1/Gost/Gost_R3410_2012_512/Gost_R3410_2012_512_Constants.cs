namespace GostCryptography.Asn1.Gost.Gost_R3410_2012_512
{
	public static class Gost_R3410_2012_512_Constants
	{
		/// <summary>
		/// Алгоритм ГОСТ Р 34.10-2012 для ключей длины 512 бит, используемый при экспорте/импорте ключей.
		/// </summary>
		public static readonly OidValue KeyAlgorithm = OidValue.FromString("1.2.643.7.1.1.1.2");

		/// <summary>
		/// Алгоритм Диффи-Хеллмана на базе эллиптической кривой для ключей длины 512 бит.
		/// </summary>
		public static readonly OidValue DhAlgorithm = OidValue.FromString("1.2.643.7.1.1.6.2");

		/// <summary>
		/// Алгоритм цифровой подписи ГОСТ Р 34.10-2012 для ключей длины 512 бит.
		/// </summary>
		public static readonly OidValue SignatureAlgorithm = OidValue.FromString("1.2.643.7.1.1.3.3");

		/// <summary>
		/// Функция хэширования ГОСТ Р 34.11-2012, длина выхода 512 бит.
		/// </summary>
		public static readonly OidValue HashAlgorithm = OidValue.FromString("1.2.643.7.1.1.2.3");
	}
}