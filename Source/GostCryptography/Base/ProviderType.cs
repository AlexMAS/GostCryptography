using System.Collections.Generic;

namespace GostCryptography.Base
{
	/// <summary>
	/// Типы криптографических провайдеров.
	/// </summary>
	public enum ProviderType
	{
		/// <summary>
		/// Infotecs Cryptographic Service Provider.
		/// </summary>
		VipNet = 2,

		/// <summary>
		/// Infotecs GOST 2012/512 Cryptographic Service Provider.
		/// </summary>
		VipNet_2012_512 = 77,

		/// <summary>
		/// Infotecs GOST 2012/1024 Cryptographic Service Provider.
		/// </summary>
		VipNet_2012_1024 = 78,


		/// <summary>
		/// Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider.
		/// </summary>
		CryptoPro = 75,

		/// <summary>
		/// Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider.
		/// </summary>
		CryptoPro_2012_512 = 80,

		/// <summary>
		/// Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider.
		/// </summary>
		CryptoPro_2012_1024 = 81
	}


	/// <summary>
	/// Методы расширения <see cref="ProviderType"/>.
	/// </summary>
	public static class ProviderTypesExtensions
	{
		/// <summary>
		/// Набор провайдеров VipNet.
		/// </summary>
		public static readonly HashSet<ProviderType> VipNetProviders = new HashSet<ProviderType>
		{
			ProviderType.VipNet,
			ProviderType.VipNet_2012_512,
			ProviderType.VipNet_2012_1024
		};

		/// <summary>
		/// Набор провайдеров CryptoPro.
		/// </summary>
		public static readonly HashSet<ProviderType> CryptoProProviders = new HashSet<ProviderType>
		{
			ProviderType.CryptoPro,
			ProviderType.CryptoPro_2012_512,
			ProviderType.CryptoPro_2012_1024
		};


		/// <summary>
		/// Возвращает <see langword="true"/> для VipNet.
		/// </summary>
		public static bool IsVipNet(this ProviderType providerType) => VipNetProviders.Contains(providerType);

		/// <summary>
		/// Возвращает <see langword="true"/> для CryptoPro.
		/// </summary>
		public static bool IsCryptoPro(this ProviderType providerType) => CryptoProProviders.Contains(providerType);


		/// <summary>
		/// Преобразует значение в <see cref="int"/>.
		/// </summary>
		public static int ToInt(this ProviderType providerType) => (int)providerType;
	}
}