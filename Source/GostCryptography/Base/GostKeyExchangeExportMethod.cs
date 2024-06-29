namespace GostCryptography.Base
{
	/// <summary>
	/// Алгоритм экспорта общего секретного ключа ГОСТ.
	/// </summary>
	public enum GostKeyExchangeExportMethod
	{
		/// <summary>
		/// Простой экспорт ключа.
		/// </summary>
		GostKeyExport,

		/// <summary>
		/// Защищённый экспорт ключа по алгоритму КриптоПро.
		/// </summary>
		CryptoProKeyExport,

		/// <summary>
		/// Защищённый экспорт ключа по рекомендациям ТК26 (обязателен для использования с ключами ГОСТ Р 34.10-2012).
		/// </summary>
		CryptoProTk26KeyExport
	}
}