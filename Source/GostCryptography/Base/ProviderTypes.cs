using System.Collections.Generic;

namespace GostCryptography.Base
{
	/// <summary>
	/// Типы криптографических провайдеров.
	/// </summary>
	public enum ProviderTypes
	{
		/// <summary>
		/// Идентификатор типа криптографического провайдера VipNet: Infotecs Cryptographic Service Provider.
		/// </summary>
		VipNet = 2,

		/// <summary>
		/// Идентификатор типа криптографического провайдера VipNet: Infotecs GOST 2012/512 Cryptographic Service Provider.
		/// </summary>
		VipNet_2012_512 = 77,

		/// <summary>
		/// Идентификатор типа криптографического провайдера VipNet: Infotecs GOST 2012/1024 Cryptographic Service Provider.
		/// </summary>
		VipNet_2012_1024 = 78,


		/// <summary>
		/// Идентификатор типа криптографического провайдера CryptoPro: CryptoPro Cryptographic Service Provider.
		/// </summary>
		CryptoPro = 75,

		/// <summary>
		/// Идентификатор типа криптографического провайдера CryptoPro: CryptoPro GOST 2012/512 Cryptographic Service Provider.
		/// </summary>
		CryptoPro_2012_512 = 80,

		/// <summary>
		/// Идентификатор типа криптографического провайдера CryptoPro: CryptoPro GOST 2012/1024 Cryptographic Service Provider.
		/// </summary>
		CryptoPro_2012_1024 = 81
	}


	/// <summary>
	/// Методы расширения <see cref="ProviderTypes"/>.
	/// </summary>
	public static class ProviderTypesExtensions
	{
		/// <summary>
		/// Набор провайдеров VipNet.
		/// </summary>
		public static readonly HashSet<ProviderTypes> VipNetProviders = new HashSet<ProviderTypes>
		{
			ProviderTypes.VipNet,
			ProviderTypes.VipNet_2012_512,
			ProviderTypes.VipNet_2012_1024
		};

		/// <summary>
		/// Набор провайдеров CryptoPro.
		/// </summary>
		public static readonly HashSet<ProviderTypes> CryptoProProviders = new HashSet<ProviderTypes>
		{
			ProviderTypes.CryptoPro,
			ProviderTypes.CryptoPro_2012_512,
			ProviderTypes.CryptoPro_2012_1024
		};


		/// <summary>
		/// Возвращает <see langword="true"/> для VipNet.
		/// </summary>
		public static bool IsVipNet(this ProviderTypes providerType) => VipNetProviders.Contains(providerType);

		/// <summary>
		/// Возвращает <see langword="true"/> для CryptoPro.
		/// </summary>
		public static bool IsCryptoPro(this ProviderTypes providerType) => CryptoProProviders.Contains(providerType);


		/// <summary>
		/// Преобразует значение в <see cref="int"/>.
		/// </summary>
		public static int ToInt(this ProviderTypes providerType) => (int)providerType;
	}
}