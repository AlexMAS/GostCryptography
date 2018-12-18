using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1GraphicString : Asn1VarWidthCharString
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, GraphicStringTypeCode);

		public Asn1GraphicString()
			: base(GraphicStringTypeCode)
		{
		}

		public Asn1GraphicString(string data)
			: base(data, GraphicStringTypeCode)
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
			outs.EncodeCharString(base.Value, explicitTagging, Tag);
		}
	}
}