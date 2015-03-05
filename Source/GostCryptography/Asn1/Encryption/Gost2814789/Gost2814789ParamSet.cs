using GostCryptography.Asn1.Ber;

namespace GostCryptography.Asn1.Encryption.Gost2814789
{
	class Gost2814789ParamSet : Asn1ObjectIdentifier
	{
		public Gost2814789ParamSet()
		{
		}

		public Gost2814789ParamSet(int[] value)
			: base(value)
		{
		}
	}
}