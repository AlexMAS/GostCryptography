using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_R3410;

namespace GostCryptography.Asn1.Gost.Gost_R3410_2012_512
{
	public sealed class Gost_R3410_2012_512_PublicKeyType : Gost_R3410_PublicKeyType
	{
		protected override Asn1Type CreateParams()
		{
			return new Gost_R3410_2012_512_PublicKeyParams();
		}
	}
}