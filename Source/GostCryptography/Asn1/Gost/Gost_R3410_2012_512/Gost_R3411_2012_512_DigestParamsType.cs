using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_R3411;

namespace GostCryptography.Asn1.Gost.Gost_R3410_2012_512
{
	public sealed class Gost_R3411_2012_512_DigestParamsType : Gost_R3411_DigestParamsType
	{
		protected override Asn1Type CreateParams()
		{
			return new Gost_R3411_2012_512_DigestParams();
		}
	}
}