namespace GostCryptography.Asn1.Gost.Gost_R3411
{
	public abstract class Gost_R3411_DigestParamsType : GostAsn1Choice
	{
		protected override short TagForm => 0x00;

		protected override int TagIdCode => ObjectIdentifierTypeCode;
	}
}