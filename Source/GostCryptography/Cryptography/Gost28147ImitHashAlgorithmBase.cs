namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех реализаций функции вычисления имитовставки по ГОСТ 28147.
	/// </summary>
	public abstract class Gost28147ImitHashAlgorithmBase : GostKeyedHashAlgorithm
	{
		/// <summary>
		/// Размер хэша по умолчанию.
		/// </summary>
		public const int DefaultHashSize = 32;


		/// <inheritdoc />
		protected Gost28147ImitHashAlgorithmBase()
		{
			HashSizeValue = DefaultHashSize;
		}

		/// <inheritdoc />
		protected Gost28147ImitHashAlgorithmBase(int providerType) : base(providerType)
		{
			HashSizeValue = DefaultHashSize;
		}


		/// <summary>
		/// Алгоритм симметричного шифрования ключа.
		/// </summary>
		public virtual Gost28147SymmetricAlgorithmBase KeyAlgorithm { get; set; }
	}
}