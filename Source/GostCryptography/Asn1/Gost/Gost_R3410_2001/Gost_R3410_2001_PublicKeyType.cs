using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_R3410;

namespace GostCryptography.Asn1.Gost.Gost_R3410_2001
{
	public sealed class Gost_R3410_2001_PublicKeyType : Gost_R3410_PublicKeyType
	{
		protected override Asn1Type CreateParams()
		{
			return new Gost_R3410_2001_PublicKeyParams();
		}
	}
}