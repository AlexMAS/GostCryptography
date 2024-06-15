using System.Security.Cryptography;

using GostCryptography.Base;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Базовый класс для всех реализаций симметричного шифрования по ГОСТ 28147-89.
	/// </summary>
	public abstract class Gost_28147_89_SymmetricAlgorithmBase : GostSymmetricAlgorithm
	{
		public const int DefaultKeySize = 256;
		public const int DefaultBlockSize = 64;
		public const int DefaultFeedbackSize = 64;
        public const int DefaultIvSize = DefaultBlockSize / 8;
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
	}
}