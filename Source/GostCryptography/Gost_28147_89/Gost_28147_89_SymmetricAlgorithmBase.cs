using System.Security.Cryptography;

using GostCryptography.Base;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Базовый класс для всех реализаций симметричного шифрования по ГОСТ 28147-89.
	/// </summary>
	public abstract class Gost_28147_89_SymmetricAlgorithmBase : GostSymmetricAlgorithm
	{
		public const int DefaultIvSize = 8;
		public const int DefaultKeySize = 256;
		public const int DefaultBlockSize = 64;
		public const int DefaultFeedbackSize = 64;
		public static readonly KeySizes[] DefaultLegalKeySizes = { new KeySizes(DefaultKeySize, DefaultKeySize, 0) };
		public static readonly KeySizes[] DefaultLegalBlockSizes = { new KeySizes(DefaultBlockSize, DefaultBlockSize, 0) };


		/// <inheritdoc />
		protected Gost_28147_89_SymmetricAlgorithmBase()
		{
			InitDefaults();
		}

		/// <inheritdoc />
		protected Gost_28147_89_SymmetricAlgorithmBase(ProviderType providerType) : base(providerType)
		{
			InitDefaults();
		}


		private void InitDefaults()
		{
			KeySizeValue = DefaultKeySize;
			BlockSizeValue = DefaultBlockSize;
			FeedbackSizeValue = DefaultFeedbackSize;
			LegalBlockSizesValue = DefaultLegalBlockSizes;
			LegalKeySizesValue = DefaultLegalKeySizes;
		}


		/// <summary>
		/// Хэширует секретный ключ.
		/// </summary>
		public abstract byte[] ComputeHash(HashAlgorithm hash);

		/// <summary>
		/// Экспортирует (шифрует) секретный ключ.
		/// </summary>
		/// <param name="keyExchangeAlgorithm">Общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		public abstract byte[] EncodePrivateKey(Gost_28147_89_SymmetricAlgorithmBase keyExchangeAlgorithm, GostKeyExchangeExportMethod keyExchangeExportMethod);

		/// <summary>
		/// Импортирует (дешифрует) секретный ключ.
		/// </summary>
		/// <param name="encodedKeyExchangeData">Зашифрованный общий секретный ключ.</param>
		/// <param name="keyExchangeExportMethod">Алгоритм экспорта общего секретного ключа.</param>
		public abstract SymmetricAlgorithm DecodePrivateKey(byte[] encodedKeyExchangeData, GostKeyExchangeExportMethod keyExchangeExportMethod);
	}
}