using GostCryptography.Base;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Базовый класс для всех реализаций функции вычисления имитовставки по ГОСТ 28147-89.
	/// </summary>
	public abstract class Gost_28147_89_ImitHashAlgorithmBase : GostKeyedHashAlgorithm
	{
		/// <summary>
		/// Размер хэша по умолчанию.
		/// </summary>
		public const int DefaultHashSize = 32;


		/// <inheritdoc />
		protected Gost_28147_89_ImitHashAlgorithmBase()
		{
			HashSizeValue = DefaultHashSize;
		}

		/// <inheritdoc />
		protected Gost_28147_89_ImitHashAlgorithmBase(int providerType) : base(providerType)
		{
			HashSizeValue = DefaultHashSize;
		}


		/// <summary>
		/// Алгоритм симметричного шифрования ключа.
		/// </summary>
		public virtual Gost_28147_89_SymmetricAlgorithmBase KeyAlgorithm { get; set; }
	}
}