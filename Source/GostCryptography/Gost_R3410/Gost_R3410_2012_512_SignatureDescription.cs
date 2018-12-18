using GostCryptography.Base;
using GostCryptography.Gost_R3411;

namespace GostCryptography.Gost_R3410
{
	/// <summary>
	/// Информация о свойствах цифровой подписи ГОСТ Р 34.10-2012/512.
	/// </summary>
	public sealed class Gost_R3410_2012_512_SignatureDescription : GostSignatureDescription
	{
		/// <inheritdoc />
		public Gost_R3410_2012_512_SignatureDescription()
		{
			KeyAlgorithm = typeof(Gost_R3410_2012_512_AsymmetricAlgorithm).AssemblyQualifiedName;
			DigestAlgorithm = typeof(Gost_R3411_2012_512_HashAlgorithm).AssemblyQualifiedName;
			FormatterAlgorithm = typeof(GostSignatureFormatter).AssemblyQualifiedName;
			DeformatterAlgorithm = typeof(GostSignatureDeformatter).AssemblyQualifiedName;
		}
	}
}