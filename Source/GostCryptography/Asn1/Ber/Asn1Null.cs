using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public class Asn1Null : Asn1Type
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, NullTypeCode);
		public static readonly Asn1Null NullValue = new Asn1Null();

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			if (explicitTagging)
			{
				MatchTag(buffer, Tag);
			}

			buffer.TypeCode = NullTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Tag, len);
			}

			return len;
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			if (explicitTagging)
			{
				outs.EncodeTag(Tag);
			}

			outs.EncodeLength(0);
		}

		public override string ToString()
		{
			return "NULL";
		}
	}
}