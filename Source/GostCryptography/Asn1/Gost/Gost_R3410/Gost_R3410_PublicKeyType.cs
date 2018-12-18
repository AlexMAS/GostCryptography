namespace GostCryptography.Asn1.Gost.Gost_R3410
{
	public abstract class Gost_R3410_PublicKeyType : GostAsn1Choice
	{
		protected override short TagForm => 0x20;

		protected override int TagIdCode => SequenceTypeCode;
	}
}