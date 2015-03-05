using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Базовый класс для всех реализаций алгоритма хэширования ГОСТ Р 34.11.
	/// </summary>
	public abstract class Gost3411HashAlgorithmBase : HashAlgorithm
	{
		public const int DefaultHashSizeValue = 256;

		protected Gost3411HashAlgorithmBase()
		{
			HashSizeValue = DefaultHashSizeValue;
		}
	}
}