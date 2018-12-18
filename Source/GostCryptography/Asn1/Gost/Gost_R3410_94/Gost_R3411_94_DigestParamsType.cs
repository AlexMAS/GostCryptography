using GostCryptography.Asn1.Ber;
using GostCryptography.Asn1.Gost.Gost_R3411;

namespace GostCryptography.Asn1.Gost.Gost_R3410_94
{
	public sealed class Gost_R3411_94_DigestParamsType : Gost_R3411_DigestParamsType
	{
		protected override Asn1Type CreateParams()
		{
			return new Gost_R3411_94_DigestParams();
		}
	}
}