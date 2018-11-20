using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1ChoiceExt : Asn1OpenType
	{
		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			base.Decode(buffer, false, 0);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			return base.Encode(buffer, false);
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			base.Encode(outs, false);
		}
	}
}