namespace GostCryptography.Base
{
	/// <summary>
	/// Алгоритм экспорта общего секретного ключа ГОСТ.
	/// </summary>
	public enum GostKeyExchangeExportMethod
	{
		/// <summary>
		/// Простой экспорт ключа по ГОСТ 28147-89.
		/// </summary>
		GostKeyExport,

		/// <summary>
		/// Защищённый экспорт ключа по алгоритму КриптоПро.
		/// </summary>
		CryptoProKeyExport
	}
}