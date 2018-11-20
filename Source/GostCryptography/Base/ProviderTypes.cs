namespace GostCryptography.Base
{
	/// <summary>
	/// Типы криптографических провайдеров.
	/// </summary>
	public static class ProviderTypes
	{
		/// <summary>
		/// Идентификатор типа криптографического провайдера VipNet: Infotecs Cryptographic Service Provider.
		/// </summary>
		public const int VipNet = 2;

		/// <summary>
		/// Идентификатор типа криптографического провайдера VipNet: Infotecs GOST 2012/512 Cryptographic Service Provider.
		/// </summary>
		public const int VipNet_2012_512 = 77;

		/// <summary>
		/// Идентификатор типа криптографического провайдера VipNet: Infotecs GOST 2012/1024 Cryptographic Service Provider.
		/// </summary>
		public const int VipNet_2012_1024 = 78;

		/// <summary>
		/// Идентификатор типа криптографического провайдера CryptoPro.
		/// </summary>
		public const int CryptoPro = 75;
	}
}