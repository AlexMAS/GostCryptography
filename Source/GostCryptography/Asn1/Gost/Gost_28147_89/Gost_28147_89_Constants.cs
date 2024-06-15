namespace GostCryptography.Asn1.Gost.Gost_28147_89
{
	public static class Gost_28147_89_Constants
	{
		/// <summary>
		/// Алгоритм шифрования ГОСТ 28147-89.
		/// </summary>
		public static readonly OidValue EncryptAlgorithm = OidValue.FromString("1.2.643.2.2.21");

		/// <summary>
		/// Алгоритм шифрования по ГОСТ Р 34.12-2015 Магма.
		/// </summary>
		public static readonly OidValue EncryptAlgorithmMagma = OidValue.FromString("1.2.643.7.1.1.5.1");

		/// <summary>
		/// Алгоритм шифрования по ГОСТ Р 34.12-2015 Кузнечик.
		/// </summary>
		public static readonly OidValue EncryptAlgorithmKuznyechik = OidValue.FromString("1.2.643.7.1.1.5.2");
	}
}