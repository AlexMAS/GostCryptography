using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_R3411;

namespace GostCryptography.Asn1.Gost.Gost_R3410_2001
{
	public sealed class Gost_R3411_2001_DigestParamsType : Gost_R3411_DigestParamsType
	{
		protected override Asn1Type CreateParams()
		{
			return new Gost_R3411_2001_DigestParams();
		}
	}
}