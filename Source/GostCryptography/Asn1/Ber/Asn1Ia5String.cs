using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1Ia5String : Asn18BitCharString
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, Ia5StringTypeCode);

		public Asn1Ia5String()
			: base(Ia5StringTypeCode)
		{
		}

		public Asn1Ia5String(string data)
			: base(data, Ia5StringTypeCode)
		{
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			Decode(buffer, explicitTagging, implicitLength, Tag);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			return Encode(buffer, explicitTagging, Tag);
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			outs.EncodeCharString(Value, explicitTagging, Tag);
		}
	}
}