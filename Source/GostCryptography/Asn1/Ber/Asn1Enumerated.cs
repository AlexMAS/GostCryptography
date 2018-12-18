using System;

namespace GostCryptography.Asn1.Ber
{
	[Serializable]
	public abstract class Asn1Enumerated : Asn1Type
	{
		public const int Undefined = -999;
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, EnumeratedTypeCode);

		[NonSerialized]
		public int Value;

		public Asn1Enumerated()
		{
			Value = Undefined;
		}

		public Asn1Enumerated(int value)
		{
			Value = value;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var length = explicitTagging ? MatchTag(buffer, Tag) : implicitLength;
			Value = (int)Asn1RunTime.DecodeIntValue(buffer, length, true);
			buffer.TypeCode = EnumeratedTypeCode;
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = buffer.EncodeIntValue(Value);

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

			outs.EncodeIntValue(Value, true);
		}

		public virtual bool Equals(int value)
		{
			return (Value == value);
		}

		public override bool Equals(object value)
		{
			var enumerated = value as Asn1Enumerated;

			return (enumerated != null && Value == enumerated.Value);
		}

		public override int GetHashCode()
		{
			return Value.GetHashCode();
		}

		public virtual int ParseValue(string value)
		{
			return -1;
		}

		public override string ToString()
		{
			return null;
		}
	}
}