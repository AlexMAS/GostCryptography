using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_R3410;

namespace GostCryptography.Asn1.Gost.Gost_R3410_94
{
	public sealed class Gost_R3410_94_DhPublicKeyType : Gost_R3410_PublicKeyType
	{
		protected override Asn1Type CreateParams()
		{
			return new Gost_R3410_94_PublicKeyParams();
		}
	}
}