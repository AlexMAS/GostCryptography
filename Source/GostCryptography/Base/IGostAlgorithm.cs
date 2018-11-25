namespace GostCryptography.Base
{
	/// <summary>
	/// Алгоритм ГОСТ.
	/// </summary>
	public interface IGostAlgorithm
	{
		/// <summary>
		/// Тип криптографического провайдера.
		/// </summary>
		ProviderTypes ProviderType { get; }

		/// <summary>
		/// Наименование криптографического алгоритма.
		/// </summary>
		string AlgorithmName { get; }
	}
}