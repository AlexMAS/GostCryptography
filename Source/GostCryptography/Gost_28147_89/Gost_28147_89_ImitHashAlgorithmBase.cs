using GostCryptography.Base;

namespace GostCryptography.Gost_28147_89
{
	/// <summary>
	/// Базовый класс для всех реализаций функции вычисления имитовставки по ГОСТ 28147-89.
	/// </summary>
	public abstract class Gost_28147_89_ImitHashAlgorithmBase : GostKeyedHashAlgorithm
	{
		/// <inheritdoc />
		protected Gost_28147_89_ImitHashAlgorithmBase(int hashSize) : base(hashSize)
		{
		}

		/// <inheritdoc />
		protected Gost_28147_89_ImitHashAlgorithmBase(ProviderType providerType, int hashSize) : base(providerType, hashSize)
		{
		}


		/// <summary>
		/// Алгоритм симметричного шифрования ключа.
		/// </summary>
		public virtual Gost_28147_89_SymmetricAlgorithmBase KeyAlgorithm { get; set; }
	}
}