using System.Security.Cryptography;

namespace GostCryptography.Cryptography
{
	/// <summary>
	/// Информация о свойствах цифровой подписи ГОСТ Р 34.10-2001.
	/// </summary>
	public sealed class GostSignatureDescription : SignatureDescription
	{
		public GostSignatureDescription()
		{
			KeyAlgorithm = typeof(Gost3410AsymmetricAlgorithm).AssemblyQualifiedName;
			DigestAlgorithm = typeof(Gost3411HashAlgorithm).AssemblyQualifiedName;
			FormatterAlgorithm = typeof(GostSignatureFormatter).AssemblyQualifiedName;
			DeformatterAlgorithm = typeof(GostSignatureDeformatter).AssemblyQualifiedName;
		}
	}
}